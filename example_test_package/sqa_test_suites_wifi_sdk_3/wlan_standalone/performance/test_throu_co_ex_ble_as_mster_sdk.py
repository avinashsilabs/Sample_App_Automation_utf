import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.defaults import defaults
import string
import random
from random import randint
from utf.utils.iperf.iperf_utils import ping
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.performance.test_throughput_co_ex_sdk import DLPing
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.performance.test_throughput_co_ex_sdk import ULPing


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K 
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, iteration_count=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, bt_dut=None,
                 test_case_no=None, ble_client=None, ble_conn=None, utf_constants=None, mode=None, ble_adv_as_master=None,
                 ble_data_transfer=None, ssl_server=None, ssl_data_transfer=None, ble_client_address=None,
                 setting_phy=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.iteration_count = iteration_count
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.ssl_data_transfer = ssl_data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.bt_dut = bt_dut
        self.ble_client = ble_client
        self.ble_conn = ble_conn
        self.ble_adv_as_master = ble_adv_as_master
        self.utf_constants = utf_constants
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None
        self.mode = mode
        self.ble_client_address = ble_client_address
        self.ble_data_transfer = ble_data_transfer
        self.ssl_server = ssl_server
        self.setting_phy = setting_phy

    def run(self):
        if self.test_case_no == 20740 or self.test_case_no == 20750:
            transfer_type = 1
            protocol = 6
            throughput_type = 1
            size = 1460

        if self.test_case_no == 20741 or self.test_case_no == 20751:
            transfer_type = 1
            protocol = 6
            throughput_type = 3
            size = 1460

        if self.test_case_no == 20738 or self.test_case_no == 20748:
            transfer_type = 2
            protocol = 17
            throughput_type = 2
            size = 1470

        if self.test_case_no == 20739 or self.test_case_no == 20749:
            transfer_type = 2
            protocol = 17
            throughput_type = 4
            size = 1470

        logger().info("starting the sniffer again")
        # self.wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=self.wifi_access_point.interfaces.wifi.channel)
        # self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(2)
        logger().info("Enabling the **** RTT 40 Command ****")
        self.wifi_client.interfaces.tc.add_delay(40)
        time.sleep(2)

        if self.ble_adv_as_master:
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
            assert bt_dut_address, "unable to fetch dut bd address...."
            time.sleep(2)
            logger().info("Set DUT in advertise mode")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)

            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")

        if self.ble_conn:
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
            assert bt_dut_address, "unable to fetch dut bd address...."
            time.sleep(2)
            logger().info("Set DUT in advertise mode")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)

            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")
            time.sleep(5)
            # See that we found our device
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
            timeout = 120
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            self.wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=ble_client_address,
                timeout=timeout,
                expected="RSI_BLE_ENHC_CONN_EVENT",
            )
            time.sleep(20)

        if self.ble_data_transfer:
            logger().info(f"BLE Data Transfer going to start")
            service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
            char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

            logger().info("================== Start BLE in DUT ====================")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
            assert bt_dut_address, "unable to fetch dut bd address...."
            time.sleep(2)
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
            while sw.elapsed_sec < 45:
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
            time.sleep(2)
            if self.setting_phy == 304288:
                self.wifi_dut.interfaces.bluetooth.ble_set_phy(self.ble_client_address, tx_phy=1, rx_phy=1, coded_phy=2)
            if self.setting_phy == 304289:
                self.wifi_dut.interfaces.bluetooth.ble_set_phy(self.ble_client_address, tx_phy=2, rx_phy=2, coded_phy=2)

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

        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                                 retry_count=3, ping_after_power_save=False,
                                                                 ping_count=self.ping_count, power_save=False)

        if self.test_case_no == 207510 or self.test_case_no == 20751 or self.test_case_no == 20748 or \
                self.test_case_no == 20749:
            logger().info(f"BLE Data Transfer is going to start")
            ble_data = ble_notify(self.wifi_dut, self.ble_client_address)
            ble_data.start()
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        if self.data_transfer:
            if self.traffic_type == "TX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.dut_addr['device_ip'],
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        timeout=timeout+2)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(5)
            if self.traffic_type == "RX":
                self.iteration_count = self.iteration_count
                for i in range(0, self.iteration_count):
                    # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_addr['device_ip'],
                                                                            protocol=self.protocol, bandwidth=bandwidth)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1, timeout=timeout + 2)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_addr['device_ip'],
                                                                             protocol=self.protocol)

                        def start_client():
                            time.sleep(1)
                            logger().info(f"***** start listening  ******")
                            self.net_perf_client.interfaces.net_perf.start()

                        client_thread1 = Thread(target=start_client, args=(), )
                        client_thread1.start()

                        # open socket and listen for data
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.set_socket_config()
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1, timeout=timeout + 2)
                        client_thread1.join()
                        logger().info("data received is successful")
                        time.sleep(3)

        if self.ssl_data_transfer:
            if self.traffic_type == "TX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                                   timeout=15)
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)
                pkt_count = 50000
                time.sleep(1)
                server_socket_no = 1
                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
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
                # self.ssl_server.interfaces.ssl.start_server()
                # server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.set_socket_config()
                # Open ssl client socket in the DUT
                time.sleep(2)
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                      protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                                   timeout=15)
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)
                socket_no = 1
                pkt_count = 50000
                duration = 60
                self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length,
                                                         duration=duration)
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

        if self.ble_adv_as_master:
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        if self.ble_conn:
            #Get the state of the dut
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected
            self.bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(2)

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

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

    def ble_adv_as_m(self):
        if self.test_case_no == 121231:
            logger().info("Enabling the **** RTT 40 Command ****")
            self.wifi_client.interfaces.tc.add_delay(40)
            time.sleep(2)
        logger().info("Initiate ble service in DUT")
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "unable to fetch dut bd address...."
        time.sleep(2)
        logger().info("Set DUT in advertise mode")
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)

        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        logger().info(f"Remote device found in scan results ,BLE scanning is successful")

    def ble_conn_as_m(self):
        if self.test_case_no == 121231:
            logger().info("Enabling the **** RTT 40 Command ****")
            self.wifi_client.interfaces.tc.add_delay(40)
            time.sleep(2)
        logger().info("Initiate ble service in DUT")
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1)
        assert bt_dut_address, "unable to fetch dut bd address...."
        time.sleep(2)
        logger().info("Set DUT in advertise mode")
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)

        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        logger().info(f"Remote device found in scan results ,BLE scanning is successful")
        time.sleep(5)
        # See that we found our device
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        self.wifi_dut.interfaces.wifi.ble_connect(
            ble_remote_dev_address=ble_client_address,
            timeout=timeout,
            expected="RSI_BLE_ENHC_CONN_EVENT",
        )
        time.sleep(35)


class ble_notify(WifiJoinThread):
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


class IperfThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None, traffic_type=None, protocol=None, net_perf_client=None, timeout=60, device_ip=None,
                 remote_ip=None, ip_version=4, async_socket=0):
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
        self.async_socket = async_socket
        self.dut_add_dict = None

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
            async_socket=self.async_socket
        )

    def run(self):
        self.run_traffic()



@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_adv_128_tcp_tx_c207446(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_adv_as_master=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_adv_128_tcp_rx_c207447(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_adv_as_master=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_adv_128_udp_tx_c207444(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_adv_as_master=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_adv_128_udp_rx_c207445(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_adv_as_master=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ble_adv_128_with_ssl_tx_ax_C207666(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client,
                              bt_dut=bt_dut, iteration_count=iter_count, traffic_type="TX", test_case_no=20750,
                              ble_adv_as_master=True, ssl_server=ssl_server, ssl_data_transfer=True
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    }
)
def test_wlan_ble_adv_128_with_ssl_rx_ax_C207667(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client, bt_dut=bt_dut,
                              iteration_count=iter_count, traffic_type="RX", test_case_no=20750, ssl_server=ssl_server,
                              ssl_data_transfer=True, ble_adv_as_master=True
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_128_tcp_tx_c200746(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_128_tcp_rx_c200747(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_128_udp_tx_c200744(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_128_udp_rx_c200745(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ble_conn_128_with_ssl_tx_ax_C200766(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client,
                              bt_dut=bt_dut, iteration_count=iter_count, traffic_type="TX", test_case_no=20750,
                              ble_conn=True, ssl_server=ssl_server, ssl_data_transfer=True
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    }
)
def test_wlan_ble_conn_128_with_ssl_rx_ax_C200767(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client, bt_dut=bt_dut,
                              iteration_count=iter_count, traffic_type="RX", test_case_no=20750, ssl_server=ssl_server,
                              ssl_data_transfer=True
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_as_m_adv_tcp_tx_rx_c200748(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_clients,
                                           utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, wifi_dut=wifi_dut, wifi_client=wifi_client, test_case_no=121231)
    wlan_obj.ble_adv_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                        wifi_access_point=wifi_access_point,
                                                        associated=wifi_dut.interfaces.wifi.associated,
                                                        retry_count=3, ping_after_power_save=False,
                                                        ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:

        ipv4_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=testcase, wifi_client=wifi_client,
                               traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=30,
                               device_ip=dut_ip, remote_ip=host_ip,
                               ip_version=4
                               )
        ipv4_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=testcase, wifi_client=wifi_client,
                               traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=30,
                               device_ip=dut_ip, remote_ip=host_ip,
                               ip_version=4, async_socket=1,
                               )
        ipv4_tx_obj.start()
        time.sleep(2)
        ipv4_rx_obj.start()
        time.sleep(10)
        ipv4_tx_obj.wait_for_exit()
        ipv4_rx_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info(f'Sniffer Capture is going to Stop')
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_as_m_tcp_tx_rx_c200749(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_clients,
                                           utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, bt_dut=bt_dut, wifi_client=wifi_client, wifi_dut=wifi_dut,
                              test_case_no=121231)

    wlan_obj.ble_conn_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                        wifi_access_point=wifi_access_point,
                                                        associated=wifi_dut.interfaces.wifi.associated,
                                                        retry_count=3, ping_after_power_save=False,
                                                        ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:

        ipv4_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=testcase, wifi_client=wifi_client,
                               traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=30,
                               device_ip=dut_ip, remote_ip=host_ip,
                               ip_version=4
                               )
        ipv4_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                               test_name=testcase, wifi_client=wifi_client,
                               traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=30,
                               device_ip=dut_ip, remote_ip=host_ip,
                               ip_version=4, async_socket=1,
                               )
        ipv4_tx_obj.start()
        time.sleep(2)
        ipv4_rx_obj.start()
        time.sleep(10)
        ipv4_tx_obj.wait_for_exit()
        ipv4_rx_obj.wait_for_exit()
        logger().info(f'Sniffer Capture is going to Stop')
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_as_m_adv_udp_tx_rx_c200750(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_clients,
                                           utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, wifi_dut=wifi_dut, wifi_client=wifi_client, test_case_no=121231)
    wlan_obj.ble_adv_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:

        ipv4_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                  test_name=testcase, wifi_client=wifi_client,
                                  traffic_type="TX", protocol="UDP", net_perf_client=net_perf_clients[0], timeout=30,
                                  device_ip=dut_ip, remote_ip=host_ip,
                                  ip_version=4
                                  )
        ipv4_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                  test_name=testcase, wifi_client=wifi_client,
                                  traffic_type="RX", protocol="UDP", net_perf_client=net_perf_clients[1], timeout=30,
                                  device_ip=dut_ip, remote_ip=host_ip,
                                  ip_version=4, async_socket=1,
                                  )
        ipv4_tx_obj.start()
        time.sleep(2)
        ipv4_rx_obj.start()
        time.sleep(10)
        ipv4_tx_obj.wait_for_exit()
        ipv4_rx_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info(f'Sniffer Capture is going to Stop')
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}}})
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_as_m_128_udp_tx_rx_c200751(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_clients,
                                            utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, bt_dut=bt_dut, wifi_client=wifi_client, wifi_dut=wifi_dut,
                              test_case_no=121231)
    wlan_obj.ble_conn_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:

        ipv4_tx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                  test_name=testcase, wifi_client=wifi_client,
                                  traffic_type="TX", protocol="TCP", net_perf_client=net_perf_clients[0], timeout=30,
                                  device_ip=dut_ip, remote_ip=host_ip,
                                  ip_version=4
                                  )
        ipv4_rx_obj = IperfThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                  test_name=testcase, wifi_client=wifi_client,
                                  traffic_type="RX", protocol="TCP", net_perf_client=net_perf_clients[1], timeout=30,
                                  device_ip=dut_ip, remote_ip=host_ip,
                                  ip_version=4, async_socket=1,
                                  )
        ipv4_tx_obj.start()
        time.sleep(2)
        ipv4_rx_obj.start()
        time.sleep(10)
        ipv4_tx_obj.wait_for_exit()
        ipv4_rx_obj.wait_for_exit()
        logger().info(f'Sniffer Capture is going to Stop')
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_as_m_adv_ping_dl_ul_c207446(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                              request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, wifi_dut=wifi_dut, wifi_client=wifi_client)
    wlan_obj.ble_adv_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:
        ping_down = DLPing(wifi_client=wifi_client, dut_ip=dut_ip, ping_count=ping_count)
        ping_up = ULPing(wifi_client=wifi_client, ping_count=ping_count, wifi_dut=wifi_dut)
        ping_down.start()
        time.sleep(1)
        ping_up.start()
        ping_down.wait_for_exit()
        ping_up.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
def test_wlan_ble_as_m_conn_ping_dl_ul_c207447(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                               request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_client, bt_dut=bt_dut, wifi_client=wifi_client, wifi_dut=wifi_dut)
    wlan_obj.ble_conn_as_m()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    dut_ip = dut_addr['device_ip']
    logger().info(f"#######=====>>>>>>>{dut_ip}")
    try:
        ping_down = DLPing(wifi_client=wifi_client, dut_ip=dut_ip, ping_count=ping_count)
        ping_up = ULPing(wifi_client=wifi_client, ping_count=ping_count, wifi_dut=wifi_dut)
        ping_down.start()
        time.sleep(1)
        ping_up.start()
        ping_down.wait_for_exit()
        ping_up.wait_for_exit()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_tcp_tx_c401701(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_data_transfer=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              setting_phy=304288)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_tcp_rx_c401702(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
                              setting_phy=304288
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_udp_tx_c401703(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
                              setting_phy=304288
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_udp_rx_c401704(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
                              setting_phy=304288
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ble_conn_data_ssl_tx_ax_c401705(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client,
                              bt_dut=bt_dut, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              ble_conn=True, ssl_server=ssl_server, ssl_data_transfer=True, setting_phy=304288
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                  Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    }
)
def test_wlan_ble_conn_data_with_ssl_rx_ax_c401706(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client, bt_dut=bt_dut,
                              iteration_count=iter_count, traffic_type="RX", test_case_no=20740, ssl_server=ssl_server,
                              ssl_data_transfer=True, setting_phy=304288
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})


@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_phy2_tcp_tx_c401707(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                           protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_data_transfer=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              setting_phy=304289)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_phy2_tcp_rx_c401708(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                           protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
                              setting_phy=304289
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_phy2_udp_tx_c401709(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                           protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
                              setting_phy=304289
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
def test_wlan_ble_conn_data_phy2_udp_rx_c401710(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                           protocol, utf_constants, request, sl_collections, ble_client, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_client=ble_client, bt_dut=bt_dut,
                              ble_conn=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
                              setting_phy=304289
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
def test_wlan_ble_conn_data_phy2_ssl_tx_ax_c401711(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                  request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client,
                              bt_dut=bt_dut, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
                              ble_conn=True, ssl_server=ssl_server, ssl_data_transfer=True, setting_phy=304289
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    }
)
def test_wlan_ble_conn_data_phy2_ssl_rx_ax_c401712(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                   utf_constants,
                                                   request, sl_collections, ble_client, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_client=ble_client, bt_dut=bt_dut,
                              iteration_count=iter_count, traffic_type="RX", test_case_no=20740, ssl_server=ssl_server,
                              ssl_data_transfer=True, setting_phy=304289
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_client.interfaces.tc.delete_delay()
        time.sleep(2)