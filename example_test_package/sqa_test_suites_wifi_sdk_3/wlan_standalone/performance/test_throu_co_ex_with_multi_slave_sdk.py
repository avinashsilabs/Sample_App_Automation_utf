import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xTCPIPFeatureBitMap,
    Si91xBTFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap)
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
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, bt_dut=None, ble_dut=None,
                 test_case_no=None, ble_client=None, ble_conn=None, utf_constants=None, mode=None, ble_adv_128=None,
                 ble_data_transfer=None, ssl_server=None, ssl_data_transfer=None, ble_client_address=None,
                 ble_data_transfer_with_nrf=None, setting_phy=None, ble_clients=None):
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
        self.ble_clients = ble_clients
        self.ble_conn = ble_conn
        self.ble_adv_128 = ble_adv_128
        self.utf_constants = utf_constants
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None
        self.mode = mode
        # self.transfer_type = transfer_type
        self.ble_client_address = ble_client_address
        self.ble_data_transfer = ble_data_transfer
        self.ssl_server = ssl_server
        self.ble_dut = ble_dut
        self.ble_data_transfer_with_nrf = ble_data_transfer_with_nrf
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
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(2)
        logger().info("Enabling the **** RTT 40 Command ****")
        self.wifi_client.interfaces.tc.add_delay(40)
        time.sleep(2)

        if self.ble_adv_128:
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "unable to fetch dut bd address...."

            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128)

            logger().info("Start smp scan from the remote device ====>>>> 1")
            bt_client_address_1 = self.ble_clients[0].interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address_1 is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_clients[0].interfaces.bluetooth.stop_scanning()

            logger().info("Start smp scan from the remote device ====>>>> 2")
            bt_client_address_2 = self.ble_clients[1].interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address_2 is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_clients[1].interfaces.bluetooth.stop_scanning()

            # See that we found our device
            logger().info("Check the dut is listed in remote device_1...")
            found_devices_1 = self.ble_clients[0].interfaces.bluetooth.get_devices()
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices_1

            logger().info("Check the dut is listed in remote device_1...")
            found_devices_2 = self.ble_clients[1].interfaces.bluetooth.get_devices()
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices_2

        if self.ble_conn:
            conn_params = {
                "min_conn_interval": self.utf_constants.get("min_conn_interval"),
                "max_conn_interval": self.utf_constants.get("max_conn_interval"),
                "conn_latency": 0,
                "supervision_timeout": self.utf_constants.get("supervision_timeout")}
            logger().info("Initiate ble service in DUT")
            bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_gatt_start()
            assert bt_dut_address, "unable to fetch dut bd address...."

            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128)

            logger().info("Start smp scan from the remote device ====>>>> 1")
            bt_client_address_1 = self.ble_clients[0].interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            logger().info(f"DUT MAC Address ====>>>> {bt_client_address_1}")
            assert bt_client_address_1 is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_clients[0].interfaces.bluetooth.stop_scanning()

            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 45:
                found_devices = self.ble_clients[0].interfaces.bluetooth.get_devices()
                if bt_dut_address in found_devices and \
                        found_devices[bt_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data:
                    device_found = True
                    break

            self.ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "no device found"

            self.ble_clients[0].interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                         min_conn_interval=conn_params["min_conn_interval"],
                                                         max_conn_interval=conn_params["max_conn_interval"],
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])

            assert bt_dut_address, "unable to connect to the given address"
            time.sleep(12)
            logger().info("======= get connection state")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"
            time.sleep(2)
            logger().info("Set DUT in advertise mode")
            self.bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128)
            logger().info("Start smp scan from the remote device ====>>>> 2")
            bt_client_address_2 = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            logger().info(f"DUT mac ====>>>>> {bt_client_address_2}")
            assert bt_client_address_2 is not None
            time.sleep(5)
            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            logger().info("Check the dut is listed...")
            found_devices_2 = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"available devices {found_devices_2}")
            assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices_2

            self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                         min_conn_interval=200,
                                                         max_conn_interval=200,
                                                         conn_latency=conn_params["conn_latency"],
                                                         supervision_timeout=conn_params["supervision_timeout"])

            assert bt_dut_address, "unable to connect to the given address"
            time.sleep(12)

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
                self.ble_dut.interfaces.bluetooth.ble_set_phy(self.ble_client_address, tx_phy=1, rx_phy=1, coded_phy=2)
            if self.setting_phy == 304289:
                self.ble_dut.interfaces.bluetooth.ble_set_phy(self.ble_client_address, tx_phy=2, rx_phy=2, coded_phy=2)

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

        if self.test_case_no == 220740 or self.test_case_no == 220741 or self.test_case_no == 220738 or \
                self.test_case_no == 220739:
            logger().info(f"BLE Data Transfer is going to start")
            ble_data = BleNotifyNRF(self.ble_client)
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

        if self.ble_adv_128:
            self.bt_dut.interfaces.bluetooth.ble_stop_advertising()

        if self.ble_conn:
            self.bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
            time.sleep(2)

        if self.ble_data_transfer:
            # data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
            # logger().info(f"unsubcribing the ble notifications")
            # self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            # self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            # time.sleep(1)
            #
            # logger().info("====================== Validate Data ===========================")
            # notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
            # logger().info(f' *********************** Notification is {notifications} ***********************')
            # assert len(notifications) > 0, "received data is empty"
            # assert notifications[0] == data, "failed to fetch data"
            #
            # logger().info("******************** ble_remove_service ***********************")
            # self.wifi_dut.interfaces.wifi.ble_remove_service()

            logger().info("================== Disconnecting from DUT ========================")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            self.ble_client.interfaces.bluetooth.close()

        if self.ble_data_transfer_with_nrf:
            logger().info("******************** ble_remove_service ***********************")
            self.wifi_dut.interfaces.wifi.ble_remove_service()

            logger().info("================== Disconnecting from DUT ========================")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

    def ble_advertise_128(self):
        if self.test_case_no == 121231:
            logger().info("Enabling the **** RTT 40 Command ****")
            self.wifi_client.interfaces.tc.add_delay(40)
            time.sleep(2)

        logger().info("Initiate ble service in DUT")
        bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "unable to fetch dut bd address...."

        logger().info("Set DUT in advertise mode")
        self.bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128)

        logger().info("Start smp scan from the remote device")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)
        logger().info("stop scanning ....")
        self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        logger().info("Check the dut is listed...")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices

    def ble_connection_128(self):
        if self.test_case_no == 121232:
            logger().info("Enabling the **** RTT 40 Command ****")
            self.wifi_client.interfaces.tc.add_delay(40)
            time.sleep(2)

        logger().info(f"BLE connection process started")
        conn_params = {
            "min_conn_interval": self.utf_constants.get("min_conn_interval"),
            "max_conn_interval": self.utf_constants.get("max_conn_interval"),
            "conn_latency": 0,
            "supervision_timeout": self.utf_constants.get("supervision_timeout")}
        logger().info("Initiate ble service in DUT")
        bt_dut_address = self.bt_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "unable to fetch dut bd address...."

        logger().info("Set DUT in advertise mode")
        self.bt_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_type=128)

        logger().info("Start smp scan from the remote device")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)
        logger().info("stop scanning ....")
        self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        logger().info("Check the dut is listed...")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        assert self.bt_dut.interfaces.bluetooth.ble_address in found_devices

        self.ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                     min_conn_interval=conn_params["min_conn_interval"],
                                                     max_conn_interval=conn_params["max_conn_interval"],
                                                     conn_latency=conn_params["conn_latency"],
                                                     supervision_timeout=conn_params["supervision_timeout"])

        assert bt_dut_address, "unable to connect to the given address"
        time.sleep(12)


class ble_notify(WifiJoinThread):
    def __init__(self, wifi_dut, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client_address = ble_client_address

    def run(self):
        data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
        address2 = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        self.wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)
        sw = Stopwatch()
        while sw.elapsed_sec < 35:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data, ble_remote_dev_address=self.ble_client_address)
            time.sleep(0.5)


class BleNotifyNRF(WifiJoinThread):
    def __init__(self, ble_client):
        super().__init__()
        self.ble_client = ble_client

    def run(self):
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(
            '(//android.widget.RelativeLayout[@resource-id="no.nordicsemi.android.mcp:id/service_main"])[3]')
        time.sleep(42)
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications()
        time.sleep(2)


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

class DLPing(ThreadBase):

    def __init__(self, wifi_client=None, dut_ip=None, ping_count=None):
        super().__init__()
        self.wifi_client = wifi_client
        self.dut_ip = dut_ip
        self.ping_count = ping_count

    def run(self):
        rc, stdout, stderr = self.wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {self.ping_count} {self.dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")


class ULPing(ThreadBase):

    def __init__(self, wifi_client=None, wifi_dut=None, ping_count=None):
        super().__init__()
        self.wifi_client = wifi_client
        self.wifi_dut = wifi_dut
        self.ping_count = ping_count

    def run(self):
        host_ip =self. wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote IP Address :{host_ip}")
        self.wifi_dut.interfaces.wifi.ping( server_ip=host_ip, num_ping_attempts=self.ping_count)



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
def test_wlan_ble_adv_128_tcp_tx_c401801(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_clients=ble_clients, bt_dut=bt_dut,
                              ble_adv_128=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20740,
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
def test_wlan_ble_adv_128_tcp_rx_c401802(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_clients=ble_clients, bt_dut=bt_dut,
                              ble_adv_128=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20741,
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
def test_wlan_ble_adv_128_udp_tx_c401803(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_clients=ble_clients, bt_dut=bt_dut,
                              ble_adv_128=True, iteration_count=iter_count, traffic_type="TX", test_case_no=20738,
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
def test_wlan_ble_adv_128_udp_rx_c401804(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, utf_constants=utf_constants,
                              ping_count=ping_count, data_transfer=True, ble_clients=ble_clients, bt_dut=bt_dut,
                              ble_adv_128=True, iteration_count=iter_count, traffic_type="RX", test_case_no=20739,
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
def test_wlan_ble_adv_128_with_ssl_tx_ax_c401805(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                request, sl_collections, ble_clients, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_clients=ble_clients,
                              bt_dut=bt_dut, iteration_count=iter_count, traffic_type="TX", test_case_no=20750,
                              ble_adv_128=True, ssl_server=ssl_server, ssl_data_transfer=True
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
def test_wlan_ble_adv_128_with_ssl_rx_ax_c401806(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                request, sl_collections, ble_clients, bt_dut, ssl_server):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, sl_collections=sl_collections,
                              utf_constants=utf_constants, ping_count=ping_count, ble_clients=ble_clients, bt_dut=bt_dut,
                              iteration_count=iter_count, traffic_type="RX", test_case_no=20750, ssl_server=ssl_server,
                              ssl_data_transfer=True, ble_adv_128=True
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

    }
)
def test_wlan_ble_adv_128_with_ping_ul_dl_c401807(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_clients=ble_clients, bt_dut=bt_dut, wifi_client=wifi_client)
    wlan_obj.ble_adv_128()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
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

    }
)
def test_wlan_ble_conn_128_with_ping_ul_dl_c401808(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, utf_constants,
                                                 request, sl_collections, ble_clients, bt_dut):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    time.sleep(2)
    wlan_obj = WifiJoinThread(ble_client=ble_clients, bt_dut=bt_dut, wifi_client=wifi_client, utf_constants=utf_constants)
    wlan_obj.ble_adv_128()
    dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                   wifi_access_point=wifi_access_point,
                                                   associated=wifi_dut.interfaces.wifi.associated,
                                                   retry_count=3, ping_after_power_save=False,
                                                   ping_count=ping_count, power_save=False)
    time.sleep(2)
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

