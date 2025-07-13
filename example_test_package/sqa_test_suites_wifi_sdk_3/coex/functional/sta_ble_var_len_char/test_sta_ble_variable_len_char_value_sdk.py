from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xCertificateType, \
    Si91xCertIdentifier
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
import string
from random import choices
import random
from threading import Thread

"""
    Author: Saurabh Sharma
"""


def logger():
    return get_logger(__name__)


class WifiThreadFunctionality(ThreadBase):
    dut_addr = {}

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, net_perf_client=None, traffic=None, qos=None, protocol=None,
                 ssl_server=None, http_server=None, index_path=None, ping_count=None, https=0):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
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
        self.https = https
        self.dut_add_dict = {}

    def run(self):
        try:
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"******** HOST IP {self.host_ip} *******")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"******** AP MAC ADDRESS {self.ap_mac_address} *******")

            WifiThreadFunctionality.dut_addr = self.sl_collections.join_to_wifi_network(
                self.wifi_dut, self.wifi_access_point, retry_count=3,
                associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case in [777944]:
                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=3,
                                                                        ip_version='ipv6')
                assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
                self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
                self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
                logger().info(f"DUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                              f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def wifi_leave(self):
        self.wifi_dut.interfaces.wifi.leave()


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, set_smp=0, switch=None, utf_constants=None, bond_info=0, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.set_smp = set_smp
        self.switch = switch
        self.utf_constants = utf_constants
        self.bond_info = bond_info
        self.ble_client_address = ble_client_address

        """ *************************** Set up DUT for BLE advertising ***************************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp,
                                                                            bond_info=self.bond_info)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def run(self):
        if self.test_case in [777941, 777942, 777943]:
            logger().info(f"Advertising the DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
            self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address)
            logger().info("*********** Checking for BLE Stability ************ ")
            time.sleep(60)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if self.test_case in [777944, 777945, 777946]:
            self.ble_client_address = self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                timeout=20, mode='master')

    def add_ble_services(self):
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)

    def resolving_services_client(self):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"

        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs, service_uid=service_uid, char_uid=char_uid)

        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        test_case_data_lengths = {
            777941: [5, 10, 15],
            777943: [100, 160, 240],
            777945: [30],
            777942: [30, 50, 80],
            777946: [60, 120, 230],
            777944: [230],
        }
        data_lengths = test_case_data_lengths.get(self.test_case, [])

        for length in data_lengths:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
            self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
            time.sleep(5)
            result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
            time.sleep(2)
            logger().info(f'Data length: {length}, Written value: {data}, Read value: {result}')

    def ble_remove_services(self):
        logger().info("****** ble_remove_services *******")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_cleanup_disconn(self):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True

        self.ble_client.interfaces.bluetooth.remove_device(self.ble_dut_address)
        self.ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Cleanup Success *******************")


class Iperf(WifiThreadFunctionality, ThreadBase):
    def __init__(self, wifi_dut=None, net_perf_client=None, wifi_client=None, protocol=None, traffic=None,
                 wifi_access_point=None, qos=None, capture_filename=None, wifi_sniffer=None, sl_collections=None,
                 sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.traffic = traffic
        self.wifi_access_point = wifi_access_point
        self.qos = qos
        self.capture_filename = capture_filename
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.ap_mac_address = None
        self.host_ip = None

    def run(self):
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"******** HOST IP {self.host_ip} *******")
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"******** AP MAC ADDRESS {self.ap_mac_address} *******")

        self.net_perf_client.interfaces.net_perf.init_client(
            host_ip=self.host_ip, device_ip=WifiThreadFunctionality.dut_addr['device_ip'], protocol=self.protocol,
            tos_value=self.traffic, time_out=75)
        logger().info(
            f"Host IP: {self.host_ip}, Dut IP: {WifiThreadFunctionality.dut_addr['device_ip']}, Protocol: {self.protocol}, "
            f"tos_value: {self.traffic}")

        def start_client():
            time.sleep(1)
            logger().info(f"***** start listening  ******")
            self.net_perf_client.interfaces.net_perf.start()

        client_thread1 = Thread(target=start_client, args=(), )
        client_thread1.start()

        self.wifi_dut.interfaces.wifi.set_socket_config()
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            local_ip=WifiThreadFunctionality.dut_addr['device_ip'],
                                            remote_ip=self.host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            size=1460, ttl=60, throughput_type=3, qos=self.qos,
                                            timeout=75, async_socket=1)
        client_thread1.join()
        logger().info("data received is successful")


class SSLThread(WifiThreadFunctionality, ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, ssl_server=None, http_server=None, index_path=None,
                 ping_count=None, https=0):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.ap_mac_address = None
        self.host_ip = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.ssl_server = ssl_server
        self.http_server = http_server
        self.index_path = index_path
        self.ping_count = ping_count
        self.https = https
        self.dut_add_dict = {}

    def run(self):
        if self.test_case in [777941, 777943]:
            local_port = 5001

            """ ***** Open ssl server socket in remote device(Raspberry pi or static device) ***** """
            self.ssl_server.interfaces.ssl.start_server(port=local_port)
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            sock = self.wifi_dut.interfaces.wifi.socket()
            logger().info(f" ******************* Sock ID {sock} ******************** ")

            """ ***** Enable ssl option for socket opened ***** """
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
                socket_fd=sock, option_level="SOL_TCP", option_name="TCP_ULP", option_val="tls_1_2")

            self.wifi_dut.interfaces.wifi.bind(
                socket_fd=sock, device_ip=WifiThreadFunctionality.dut_addr['device_ip'],
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

            if self.test_case == 777941:
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

            if self.test_case == 777943:
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
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


class HTTPThread(WifiThreadFunctionality, ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, ssl_server=None, http_server=None, index_path=None,
                 ping_count=None, https=0):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.ap_mac_address = None
        self.host_ip = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.ssl_server = ssl_server
        self.http_server = http_server
        self.index_path = index_path
        self.ping_count = ping_count
        self.https = https
        self.dut_add_dict = {}

    def run(self):
        logger().info("Method to run http download")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut, http_server=self.http_server, index_path=self.index_path,
            device_ip=WifiThreadFunctionality.dut_addr['device_ip'], https=self.https)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_ssl_tx_with_gatt_write_read_operation_c777941(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, ssl_server):
    """ Verify BLE GATT write and read Operations with less than 20-Bytes(5,10,15) Variable Length in Peripheral Role
    while WLAN SSL Tx """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=0, test_case=777941)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           ssl_server=ssl_server, wifi_sniffer=wifi_sniffer,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, test_case=777941)

        ssl_obj = SSLThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            ssl_server=ssl_server, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            wifi_client=wifi_client, test_case=777941)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.start()
        time.sleep(5)
        ble_obj.resolving_services_client()
        ssl_obj.wait_for_exit()
        ble_obj.ble_remove_services()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_ssl_rx_with_gatt_write_read_operation_c777943(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, ssl_server):
    """ Verify BLE GATT write and read operation with 100, 160, 240 bytes variable length in Peripheral while SSL Rx """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=0, test_case=777943)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           ssl_server=ssl_server, wifi_sniffer=wifi_sniffer,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, test_case=777943)

        ssl_obj = SSLThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                            ssl_server=ssl_server, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                            wifi_client=wifi_client, test_case=777941)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ssl_obj.start()
        time.sleep(5)
        ble_obj.resolving_services_client()
        ssl_obj.wait_for_exit()
        ble_obj.ble_remove_services()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_http_file_download_with_gatt_write_read_operation_c777945(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, http_server, index_path):
    """ Verify BLE GATT write and read operation with more than 20 bytes variable length in central role while HTTP
    file download """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=1, test_case=777945)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           http_server=http_server, wifi_sniffer=wifi_sniffer, ping_count=10,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, index_path=index_path, test_case=777945)

        http_obj = HTTPThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              http_server=http_server, wifi_sniffer=wifi_sniffer, https=0,
                              sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, index_path=index_path, test_case=777942)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        http_obj.start()
        time.sleep(20)
        ble_obj.resolving_services_client()
        http_obj.wait_for_exit()
        ble_obj.ble_remove_services()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_https_file_download_with_gatt_write_read_operation_c777942(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, http_server, index_path):
    """ Verify BLE GATT write and read operation with more than 20 bytes variable length in peripheral role while HTTPS
    file download """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=0, test_case=777942)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           http_server=http_server, wifi_sniffer=wifi_sniffer, https=1,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, index_path=index_path, test_case=777942)

        http_obj = HTTPThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              http_server=http_server, wifi_sniffer=wifi_sniffer, https=1,
                              sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, index_path=index_path, test_case=777942)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        http_obj.start()
        time.sleep(20)
        ble_obj.resolving_services_client()
        http_obj.wait_for_exit()
        ble_obj.ble_remove_services()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_tcp_rx_with_gatt_write_read_operation_c777946(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):
    """ Verify BLE GATT write and read operation with 60,120,230 bytes variable length in central role while TCP Rx """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=1, test_case=777946)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, qos=qos,
                                           protocol=protocol, wifi_sniffer=wifi_sniffer, ping_count=10,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           wifi_client=wifi_client, traffic=traffic, net_perf_client=net_perf_client,
                                           test_case=777946)
        data_transfer_obj = Iperf(
            wifi_dut=wifi_dut, net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
            traffic=traffic, wifi_access_point=wifi_access_point, qos=qos,
            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, sniffer_filter=sniffer_filter)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.resolving_services_client()
        data_transfer_obj.start()
        data_transfer_obj.wait_for_exit()
        ble_obj.ble_remove_services()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.IPv6Mode |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ipv6_state": "0"})
def test_wifi_sdk_wlan_conn_reconn_stateless_with_gatt_write_read_operation_c777944(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut):
    """ Verify BLE GATT write and read operation with 230 bytes variable length in central role while WLAN connect,
    get DHCPv6(stateless), disconnect, reconnect """

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, set_smp=1, test_case=777944)

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, ping_count=10, sl_collections=sl_collections,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, test_case=777944)

        ble_obj.add_ble_services()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wifi_leave()
        wifi_obj.start()
        ble_obj.resolving_services_client()
        wifi_obj.wait_for_exit()
        ble_obj.ble_remove_services()
        wifi_obj.wifi_leave()

        logger().info("**** Stopping the Sniffer ****")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()
