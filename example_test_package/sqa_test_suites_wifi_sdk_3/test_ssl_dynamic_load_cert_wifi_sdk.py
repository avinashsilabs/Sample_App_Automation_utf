import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    SocketOptions,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.utils import get_tls_certificate_dir
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
import threading
import time
import re
from threading import Thread
from utf.utils.thread_base import ThreadBase
from random import randint
import string
import random

def logger():
    return get_logger(__name__)


def text_generator(size=100):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class ble_data_transfer_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.count = count

    def run(self):
        data = []
        for i in range(self.count):
            data.append(text_generator(size=4))
        logger().info(f"INTO EXECUTION FOR THREAD2")
        self.ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        bt_local_name = "rs9116_test"
        logger().info("configuring bd local name....")
        self.wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name)

        logger().info("fetching bd local name....")
        bd_local_name = self.wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"bd local name is : {bd_local_name}")

        logger().info("start ble on DUT")
        ble_dut_addr = self.wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_addr is not None, "Unable to get ble_dut_address"

        logger().info("Creating new custom gatt service in DUT")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        logger().info("Adding custom characteristic declaration to the custom service")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        logger().info("Adding characteristic value attribute to the service")
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[0])

        logger().info("Start ble advertising on DUT")
        # 256(0x100), 512(0x200), 7(0x07)
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=256, ble_adv_int_max=512,
                                                            ble_adv_channel_map=7)

        logger().info(f"Begin Scanning for BLE devices")
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(2)

        ble_client_addr = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_addr)
        assert ble_client_addr is not None, "ble client address not found"
        time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(f"See that we found our device")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    self.wifi_dut.interfaces.wifi.ble_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data)
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 200}

        self.ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_addr,
                                                     min_conn_interval=conn_params["min_conn_interval"],
                                                     max_conn_interval=conn_params["max_conn_interval"],
                                                     conn_latency=conn_params["conn_latency"],
                                                     supervision_timeout=conn_params["supervision_timeout"])
        logger().info("BLE Connection success")
        time.sleep(2)

        logger().info("Configuring remote device to receive notifications from DUT")
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        services, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=services,
            service_uid=service_uid,
            char_uid=char_uid)
        assert char_path is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger().info("Subscribing to notifications on ble_client")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                     char_uid=char_uid)

        logger().info("Sending notifications from DUT")
        for i in range(self.count):
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[i])
            self.wifi_dut.interfaces.wifi.ble_notify_value(timeout=5)
            time.sleep(10)

        logger().info("Validating received notifications on ble_client")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications: {notifications}")
        notification_len = len(notifications)
        for i in range(0, notification_len):
            assert notifications[i] == data[i], "Received wrong data in ble_client"

        data.clear()
        self.ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        time.sleep(3)

class data_tx_rx_pkt_thread(ThreadBase):
    def __init__(self, wifi_dut, ssl_server, result_load_certificate, pkt_count, buffer_length, bytes_sent, count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.result_load_certificate = result_load_certificate
        self.pkt_count = pkt_count
        self.buffer_length = buffer_length
        self.bytes_sent = bytes_sent
        self.count = count

    def run(self):

        for element in self.result_load_certificate:
            for iter in range(self.count):
                socket = element + 1
                self.ssl_server.interfaces.ssl.data_receive(socket, self.pkt_count, self.buffer_length)
                if self.ssl_server.interfaces.ssl.socket_connection_status(socket):
                    self.wifi_dut.interfaces.wifi.send_data_pkts(element, self.buffer_length, self.pkt_count)
                    # self.wifi_dut.interfaces.wifi.bsdSocketSend(0, "A", socket_fd=element, data=data_sent)
                    time.sleep(10)
                    bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(element)
                    assert self.bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote " \
                                                              f"peer " \
                                                              f"not matched on socket {element} "

                else:
                    assert f"failed to connect on socket no {element}"


def join_ap(wifi_dut, wifi_access_point, wait_time=3):
    logger().info("join AP")
    ping_count = 10
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(wait_time)
    logger().info(f"wifi_join status: {status}")
    ip_fail = 1
    for count in range(3):
        try:
            device_ip = wifi_dut.interfaces.wifi.start_ip(timeout=25)
            ip_fail = 0
            break
        except:
            time.sleep(5)
            logger().info(f"Retry_count:{count}")
    assert ip_fail == 0, "Getting IP failed"
    wifi_dut.interfaces.wifi.ping(device_ip, ping_size=ping_count)
    power_save_enable = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    assert power_save_enable == 0, 'failed to enable wlan power save'
    bt_power_save, result = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
    assert bt_power_save == 0, 'failed to enable bt power save'

    return device_ip

class load_certificates_thread(ThreadBase):
    def __init__(self, wifi_dut, ssl_server, device_ip, *lst: list):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.device_ip = device_ip
        self.lst = lst

    def run(self):
        list_sock = []
        for element in self.lst:
            # ["open", 0, port1, cert1]
            index = element[1]
            if element[0] == "open":
                port = element[2]
                logger().info(f"Certificate Loading in index{index}")
                self.wifi_dut.interfaces.wifi.set_ssl_certificate(
                    str(get_tls_certificate_dir().joinpath(element[3][0])),
                    Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,cert_index=index)

                logger().info(f"SSL start server on port{port}")
                self.ssl_server.interfaces.ssl.start_server(port=port, server_cert=element[3][1],
                                                            server_key=element[3][2])
                server_ip = self.ssl_server.interfaces.ssl.server_ip

                sock = self.wifi_dut.interfaces.wifi.socket()
                # assert sock == 0, "Socket id received is wrong. expected is 0"
                # logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=index)

                # local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.device_ip, server_port=port, timeout=15)
                retrial = 0
                for retry in range(3):
                    try:
                        logger().info(f"DUT with sock id {sock} connecting to server with port number:{port}")
                        # ssl socket opened in DUT connects to the server
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=port)
                        retrial = 1
                        break
                    except:
                        if retry == 2:
                            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                            self.ssl_server.interfaces.ssl.stop_server()
                        logger().info(f"Retrying connection for {retry} times")
                        time.sleep(5)
                assert retrial == 1, "Connection to socket failed"

                list_sock.append(sock)

        logger().info(f"APPENDING INTO LIST RESULT{list_sock}")
        return list_sock


class data_tx_rx_thread(ThreadBase):
    def __init__(self, wifi_dut, ssl_server, result_load_certificate, send_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.result_load_certificate = result_load_certificate
        self.send_count = send_count

    def run(self):

        for element in self.result_load_certificate:
            for iter in range(0, self.send_count):
                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                logger().info(f"Date Sent :{data_sent}  on socket_id {element}")
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=element, data=data_sent)
                server_socket_no = element + 1
                # # SSL server receives the data over ssl socket
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                logger().info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                logger().info("Data sent by DUT and received on server is matching")
                time.sleep(5)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
        }
)

@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dynamic_load_cert_no_index_TC19638(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections
):
    """
    Verify whether we are able to load certificates and connect to secure server after module initialization
    """
    try:
        capture_filename = "test_sdk_dynamic_load_cert_no_index_TC19638"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        logger.info("Loading certificates in DUT")
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,cert_index=0)

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        #
        list_of_sock_id = []
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        retrial = 0
        for retry in range(3):
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
                retrial = 1
                break
            except:
                if retry == 2:
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    ssl_server.interfaces.ssl.stop_server()
                logger.info(f"Retrying connection for {retry} times")
                time.sleep(5)
        assert retrial == 1,"Connection to socket failed"
        list_of_sock_id.append(sock)
        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_sock_id, send_count=1)
        data.start()
        data.wait_for_exit(True)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable",  "disassociated"])
def test_wifi_sdk_dynamic_load_cert_socket_connected_state_TC19639(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections
):
    """
    Verify whether device is throwing error or not when trying to load certificate if certificate is already loaded and connected to server
    """
    try:
        capture_filename = "test_sdk_dynamic_load_cert_socket_connected_state_TC19639"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap")
        port1 = ssl_server.interfaces.ssl.config['device_port1']

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                      timeout=15)
        retrial = 0
        for retry in range(3):
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
                retrial = 1
                break
            except:
                if retry == 2:
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    ssl_server.interfaces.ssl.stop_server()
                logger.info(f"Retrying connection for {retry} times")
                time.sleep(5)
        assert retrial == 1, "Connection to socket failed"

        try:
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE)
        except Exception as error:
            error_match = re.search("status:0x1005d", str(error)).group()
            logger.info(f"DUT sent error code which was expected :{error_match}")
            assert error_match, "DUT sent wrong error code when trying to connect to ssl socket"

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_dynamic_load_new_cert_TC19640(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections
):
    """
    Verify whether device is able to connect to new server after disconnect from server & erase and loading to the new certificates
    """
    try:
        capture_filename = "test_sdk_dynamic_load_new_cert_TC19640"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        list_of_sock_id = []
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE)

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                      timeout=15)
        retrial = 0
        for retry in range(3):
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
                retrial = 1
                break
            except:
                if retry == 2:
                    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    ssl_server.interfaces.ssl.stop_server()
                logger.info(f"Retrying connection for {retry} times")
                time.sleep(5)
        assert retrial == 1, "Connection to socket failed"
        list_of_sock_id.append(sock)
        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_sock_id, send_count=1)
        data.start()
        data.wait_for_exit(True)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

        logger.info("Clearing old certificates in DUT")
        wifi_dut.interfaces.wifi.clear_certificate()
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}}
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_dynamic_load_powersave_not_enabled_TC19646(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections):
    """
    Verify Dynamic load certificate and data transfer without enable power save
    """
    try:
        capture_filename = "test_wifi_sdk_dynamic_load_powersave_not_enabled_TC19646"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        list_of_sock_id = []
        # DUT connects to AP after join_ap API is executed
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, power_save=False, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False,ping_after_ps=False)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        for cert_index in range(0,3):
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE, cert_index=cert_index)

        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device-Port2
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl server socket in remote device-Port3
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

            #Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)

            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

            list_of_sock_id.append(sock)

        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_sock_id, send_count=5)
        data.start()
        data.wait_for_exit(True)

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 4, "stack_len": 3584}}
        }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_connection_and_transfer_of_index0_index1_when_trying_loadcert_index2_TC19642(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3, sl_collections):
    """
    Verify the connection and data transfer of index0 and index1 when trying load certificate in index2
    """
    try:
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        # open/aws , index, port , cert
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        #
        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert2)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        list_of_soc_id = result_load_certificate.return_value
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        load_cert3 = ["open", 2, port3, cert3]
        check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id, send_count=10)
        check_td2 = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert3)
        check_td1.start()
        time.sleep(3)
        check_td2.start()
        time.sleep(1)
        check_td2.wait_for_exit(True)
        list_of_soc_id_1 = check_td2.return_value
        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id_1, send_count=5)
        data.start()
        data.wait_for_exit(True)
        check_td1.wait_for_exit(True)
        list_of_soc_id.extend(list_of_soc_id_1)
        for socket in list_of_soc_id:
            logger.info(f"Closing socket{socket}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket)
        ssl_server.interfaces.ssl.stop_server()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 4, "stack_len": 3584}}
        }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_connection_and_transfer_of_index0_index2_when_trying_loadcert_index1_TC19648(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3, sl_collections):
    """
    Verify the connection and data transfer of index0 and index2 when trying load certificate in index1
    """
    try:
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        # open/aws , index, port , cert
        load_cert1 = ["open", 0, port1, cert1]
        load_cert3 = ["open", 2, port3, cert3]

        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert3)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        list_of_soc_id = result_load_certificate.return_value
        check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id, send_count=10)
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        load_cert2 = ["open", 1, port2, cert2]
        check_td2 = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert2)
        check_td1.start()
        time.sleep(3)
        check_td2.start()
        time.sleep(1)
        check_td2.wait_for_exit(True)
        list_of_soc_id_1 = check_td2.return_value
        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id_1, send_count=5)
        data.start()
        data.wait_for_exit(True)
        check_td1.wait_for_exit(True)
        list_of_soc_id.extend(list_of_soc_id_1)
        logger.info(f"results of sock_id{list_of_soc_id}")
        for socket in list_of_soc_id:
            logger.info(f"Closing socket{socket}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket)
        ssl_server.interfaces.ssl.stop_server()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 4, "stack_len": 3584}}
        }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_socket","wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_socket_connection_dataTX_enable_deep_sleep_base_powersave_C19650(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                              ssl_server, logger, cert1, cert2, cert3, sl_collections):
    """
    Verify the connection and data transfer of index0, index1 & index2 after loading certificate when we enable both deep sleep command and connected based power save
    """
    try:
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        power_save = 1
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
                power_save = 0
                break
            except:
                time.sleep(5)
                logger.info(f"Retry_count:{count}")
        assert power_save == 0

        scan_status, reason = sl_collections.scan(wifi_dut, scan_status=False)
        assert scan_status, f"....Scanning for AP failed..with reason: {reason}...."

        wifi_dut.interfaces.wifi.set_performance_profile("high_performance")

        join_status, reason = sl_collections.connect(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           join_status=False)
        assert join_status, f"....Connection to the AP failed with reason: {reason}...."

        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=1,
                                                 ip_version='ipv4')
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger.info(f"....Applying performance profile mode ")
        wifi_dut.interfaces.wifi.set_performance_profile("power_save_low_latency")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        #
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        # open/aws , index, port , cert
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        load_cert3 = ["open", 2, port3, cert3]

        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert2, load_cert3)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        list_of_soc_id = result_load_certificate.return_value
        logger.info(f"Socket_id received{list_of_soc_id}")

        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id, send_count=5)
        data.start()
        data.wait_for_exit(True)

        for socket in list_of_soc_id:
            logger.info(f"Closing socket{socket}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets","wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_dynamic_load_three_ssl_sockets_TC19641(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections):
    """
    Verify whether we are able to load certificates in all 3 indexes and connect to secure server after module initialization
    """
    try:
        capture_filename = "test_sdk_dynamic_load_three_ssl_sockets_TC19c641"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                     Si91xCertificateType.SL_NET_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                     Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ssl_server.interfaces.ssl.start_server(port=port1)
        ssl_server.interfaces.ssl.start_server(port=port2)
        server_ip = ssl_server.interfaces.ssl.server_ip
        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

            #Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock,cert_index=sock_count)

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            if sock_count < 2:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
            else:
                for retry_count in range(0, 3):
                    aws_connection = 1
                    try:
                        result = wifi_dut.interfaces.wifi.dns_get(domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com",query_timeout=120,timeout=20)
                        server_ip = result.strip().decode()
                        aws_connection = 0
                        break
                    except:
                        logger.info(f"Connecting to the AWS server failed on retry count -> {retry_count}")
                        time.sleep(3)
                assert aws_connection == 0, f"Connecting to the AWS server failed"

                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=socket_port,timeout=120)

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)

        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets","wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_dynamic_load_three_ssl_sockets_multiple_iterations_TC19643(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections
):
    """
    Verify whether we are able to load the certificates after erasing certificates in all 3 indexes if we have shutdown the connect servers
    """
    try:
        capture_filename = "test_sdk_dynamic_load_three_ssl_sockets_multiple_iterations_TC19643"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        for cert_index in range(0, 2):
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                         cert_index=cert_index)

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("start_field.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                     cert_index=2)

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                     Si91xCertificateType.SL_NET_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                     Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2)

        server_ip = ssl_server.interfaces.ssl.server_ip
        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            if sock_count < 2:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
            else:
                for retry_count in range(0, 3):
                    aws_connection = 1
                    try:
                        result = wifi_dut.interfaces.wifi.dns_get(
                            domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", query_timeout=120,
                            timeout=20)
                        server_ip = result.strip().decode()
                        aws_connection = 0
                        break
                    except:
                        logger.info(f"Connecting to the AWS server failed on retry count -> {retry_count}")
                        time.sleep(3)
                assert aws_connection == 0, f"Connecting to the AWS server failed"

                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=socket_port, timeout=120)

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)

        for index in range(0, 2):
            wifi_dut.interfaces.wifi.clear_certificate(cert_index=index)

        wifi_dut.interfaces.wifi.clear_certificate()

        for cert_index in range(0, 2):
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                         cert_index=cert_index)

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("start_field.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                     cert_index=2)

        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                     Si91xCertificateType.SL_NET_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                     Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2,
                                                     )

        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_load_certs_without_erasing_multiple_times_TC19644(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections):
    """
    Try load the certificate without erasing the existing certificates in all 3 indexes and check the SSL connection and data transfer in all 3 indexes
    """
    try:
        capture_filename = "test_wifi_sdk_load_certs_without_erasing_multiple_times_TC19644"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        for iter in range(2):
            for cert_index in range(0, 2):
                wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                             Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                             cert_index=cert_index)

            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("start_field.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                         Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                         cert_index=2)

            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                         Si91xCertificateType.SL_NET_CERTIFICATE,
                                                         Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                         cert_index=2,
                                                         )
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                         Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                         Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                         cert_index=2,
                                                         )
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port1)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port2)

            server_ip = ssl_server.interfaces.ssl.server_ip
            for sock_count in range(0, 3):
                # Open ssl client socket in the DUT
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
                # Enable ssl option for socket opened
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)

                if sock_count == 0:
                    socket_port = port1
                    local_port = randint(5001, 20000)
                elif sock_count == 1:
                    socket_port = port2
                    local_port = randint(20001, 40000)
                else:
                    socket_port = port3
                    local_port = randint(40001, 60000)

                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                              timeout=60)
                if sock_count < 2:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
                else:
                    for retry_count in range(1, 3):
                        aws_connection = 1
                        try:
                            result = wifi_dut.interfaces.wifi.dns_get(
                                domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", query_timeout=120,
                                timeout=20)
                            server_ip = result.strip().decode()
                            aws_connection = 0
                            break
                        except:
                            logger.info(f"Connecting to the AWS server failed on retry count -> {retry_count}")
                            time.sleep(3)
                    assert aws_connection == 0, f"Connecting to the AWS server failed"

                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                              server_port=socket_port, timeout=120)

            if iter == 1:
                list_of_sock_id = [0,1]
                data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_sock_id, send_count=5)
                data.start()
                data.wait_for_exit(True)

            for sock_count in range(0, 3):
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)

            ssl_server.interfaces.ssl.stop_server()
            time.sleep(1)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLANOnly,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 4, "stack_len": 3584}}
        }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_thread_wifi_sdk_connection_and_transfer_of_index1_index2_when_trying_loadcert_index0_TC19649(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3, sl_collections):
    """
    Verify the connection and data transfer of index1 and index2 when trying load certificate in index0
    """
    try:
        result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                     wifi_access_point=wifi_access_point, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        # open/aws , index, port , cert
        load_cert2 = ["open", 1, port2, cert2]
        load_cert3 = ["open", 2, port3, cert3]

        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert2, load_cert3)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        list_of_soc_id = result_load_certificate.return_value
        check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id, send_count=5)
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        load_cert1 = ["open", 0, port1, cert1]
        check_td2 = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1)
        check_td1.start()
        time.sleep(8)
        check_td2.start()
        time.sleep(1)
        check_td1.wait_for_exit(True)
        check_td2.wait_for_exit(True)
        list_of_soc_id_1 = check_td2.return_value
        data = data_tx_rx_thread(wifi_dut, ssl_server, list_of_soc_id_1, send_count=5)
        data.start()
        data.wait_for_exit(True)
        check_td1.wait_for_exit(True)
        list_of_soc_id.extend(list_of_soc_id_1)
        for socket in list_of_soc_id:
            logger.info(f"Closing socket{socket}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket)
        ssl_server.interfaces.ssl.stop_server()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip()
def test_wifi_sdk_dynamic_load_powersave_enabled_testcase14(
        wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3, sl_collections
):
    """
    @param wifi_access_point:
    @param wifi_dut:
    @param ssl_server:
    @param logger:
    @param cert1:
    @param cert2:
    @param cert3:
    @return:
    """
    try:
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        for cert_index in range(1, 4):
            cert = eval("cert" + str(cert_index))
            # The below API loads ca-cert into DUT at cert index 0
            wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert[0])),
                                                         cert_index=cert_index - 1)

        # DUT gets ipaddress through DHCP process after start_ip API is executed
        device_ip = wifi_dut.interfaces.wifi.start_ip()

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        power_save_enable = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert power_save_enable == 0, 'failed to enable wlan power save'
        bt_power_save, result = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        for sock_count in range(0, 3):
            sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Enabling SSL option for the socket-id->{sock} ")

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET,
                                                     SocketOptions.SO_SSL_ENABLE,
                                                     SocketOptions.SSL_ENABLE)

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET,
                                                     SocketOptions.SO_CERT_INDEX,
                                                     eval("SocketOptions.CERT_INDEX" + str(sock_count)))
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                          timeout=15)

            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=ssl_server.interfaces.ssl,
                                                      server_port=socket_port)

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            socket_no = [1, 2, 3]
            for socket in socket_no:
                if ssl_server.interfaces.ssl.socket_connection_status(socket):
                    ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                    result = wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                    logger.info(f"Number of bytes sent by dut {result}")
                    bytes_sent = result
                    time.sleep(3)
                    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                         f"not matched on socket {socket} "

                else:
                    assert f"failed to connect on socket no {socket}"

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
            logger.info(f"Successfully closed socket_id->{sock_count}")
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["start_field.pem", "client-certificate.crt", "private-key.key"],
                              )
                         ]
                         )
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_store_config"])
@pytest.mark.store_config
def test_wifi_sdk_dynamic_load_auto_join_TC19645(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3, domain_name, sl_collections
):
    """
    Verify whether DUT is able to connect to the server with dynamic load certificate in AUTO join functionality
    """
    try:
        ping_count = 10
        capture_filename = "test_dynamic_load_auto_join_TC19645"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        for count in range(1, 3):
            try:
                scan_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Scanning to the Wifi Access Point")
                wifi_dut.interfaces.wifi.scan(ssid=None)
                scan_fail = 0
                break
            except:
                logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                time.sleep(1)
        assert scan_fail == 0, "Scanning to the AP is failed"

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Joining to the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                break
            except:
                logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        assert join_fail == 0, "Joining to the AP is failed"

        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                device_ip = wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip_fail = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        assert ip_fail == 0, "Getting IP failed"

        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable()
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a
                    break

        logger.info(f"Initiating ping to DUT ip {device_ip} after auto join is successful")
        wifi_dut.interfaces.wifi.ping(device_ip, ping_size=ping_count)

        power_save_enable = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert power_save_enable == 0, 'failed to enable wlan power save'
        bt_power_save, result = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        for cert_index in range(1, 4):
            cert = eval("cert" + str(cert_index))
            # The below API loads ca-cert into DUT at cert index 0
            wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert[0])),
                                                         cert_index=cert_index - 1)
        wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLClientCertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                     cert_index=2)
        wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLClientPrivateKey,
                                                     str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                     cert_index=2)

        logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        wifi_dut.interfaces.wifi.ping(device_ip, ping_size=ping_count)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

        for sock_count in range(0, 3):
            sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Enabling SSL option for the socket-id->{sock} ")

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET,
                                                     SocketOptions.SO_SSL_ENABLE,
                                                     SocketOptions.SSL_ENABLE)

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                     SocketOptions.TCP_MAX_RETRY)

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET,
                                                     SocketOptions.SO_CERT_INDEX,
                                                     eval("SocketOptions.CERT_INDEX" + str(sock_count)))

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                          timeout=15)
            if sock_count < 2:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=ssl_server.interfaces.ssl,
                                                          server_port=socket_port)
            else:
                result = wifi_dut.interfaces.wifi.bsdGetHostByName(url=domain_name)
                logger.info(f"dns response is {result}")
                server_ip = result.split(b"\n")[1].split(b":")[1].decode()
                for retry_count in range(1, 4):
                    try:
                        aws_connection = 1
                        logger.info("Connecting to AWS server")
                        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=socket_port)
                        aws_connection = 0
                        break
                    except:
                        logger.info(f"Connecting to the AWS server is failed on retry count -> {retry_count}")
                        time.sleep(1)
                if aws_connection:
                    logger.info("Connecting to AWS server is failed")
                    assert aws_connection == 0, "Connecting to AWS server is failed"

        socket_no = [1, 2]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            socket_no = [1, 2]
            for socket in socket_no:
                if ssl_server.interfaces.ssl.socket_connection_status(socket):
                    # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                    result = wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                    logger.info(f"Number of bytes sent by dut {result}")
                    bytes_sent = result
                    time.sleep(10)
                    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                         f"not matched on socket {socket} "
                    logger.info(
                        "Number of bytes sent by DUT and received on the remote peer are matched on socket {socket}")

                else:
                    assert f"failed to connect on socket no {socket}"

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
            logger.info(f"Successfully closed socket_id->{sock_count}")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.config_enable(config=0)

        ssl_server.interfaces.ssl.stop_server()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}, }})
def test_wifi_sdk_load_cert_with_wlan_ble_in_connected_state_C19652(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                           ssl_server,
                                                           wifi_client, logger, cert1, sl_collections):
    """
    Verify whether DUT is able to load certificate with WLAN and BLE in connected state without power save
    """
    try:
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        data1 = "testcase__bledatatransfer_&_loadcertificate__19652"
        ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        bt_local_name = "test_C19652"
        logger.info("configuring bd local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name)

        logger.info("fetching bd local name....")
        bd_local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger.info(f"bd local name is : {bd_local_name}")

        logger.info("start ble on DUT")
        ble_dut_addr = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_addr is not None, "Unable to get ble_dut_address"

        logger.info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        logger.info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        logger.info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        logger.info("Start ble advertising on DUT")
        # 256(0x100), 512(0x200), 7(0x07)
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7)

        logger.info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)

        ble_client_addr = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_addr)
        assert ble_client_addr is not None, "ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger.info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 200}

        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_addr,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        logger.info("BLE Connection success")
        time.sleep(2)

        logger.info("Configuring remote device to receive notifications from DUT")
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        services, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=services,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        assert char_path is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger.info("Subscribing to notifications on ble_client")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)

        logger.info("Sending 50 bytes of data from DUT")
        wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data1)

        # read value - Notifications not enabled
        result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        assert result == data1

        logger.info("Get ble device state")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "Ble device is not connected"
        logger.info(" Connected to the BLE device ")

        ping_count = 10
        wifi_dut.interfaces.wifi.scan(ssid=None)
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(5)
        logger.info(f"wifi_join status: {status}")
        mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
        ip_fail = 1
        for count in range(3):
            try:
                device_ip = wifi_dut.interfaces.wifi.start_ip(timeout=25)
                ip_fail = 0
                break
            except:
                time.sleep(5)
                logger.info(f"Retry_count:{count}")
        assert ip_fail == 0, "Getting IP failed"
        logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        wifi_dut.interfaces.wifi.ping(device_ip, ping_size=ping_count)

        load_cert1 = ["open", 0, port1, cert1]
        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, load_cert1)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        logger.info(f"Loading certificate{result_load_certificate}")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0)
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_wifi_sdk_BLE_connectivity_data_tx_after_loadcert0_C19653(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                         ssl_server,
                                                         wifi_client, logger, cert1, sl_collections):
    """
    Verify the BLE connectivity and data transfer after loading the certificate and connect to SSL server
    """
    try:
        logger.info(f"test_sdk_BLE_connectivity_data_tx_after_loadcert0_C19653")
        ping_count = 10
        check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=12)
        check_td1.start()
        time.sleep(2)
        device_ip = join_ap(wifi_dut, wifi_access_point)

        port = ssl_server.interfaces.ssl.config['device_port1']

        wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0)
        power_save_enable = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert power_save_enable == 0, 'failed to enable wlan power save'
        bt_power_save, result = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        ssl_server.interfaces.ssl.start_server(port=port, server_cert=cert1[1], server_key=cert1[2])

        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                 SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                 SocketOptions.CERT_INDEX0)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port,
                                      timeout=15)
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=ssl_server.interfaces.ssl,
                                                      server_port=port)
        except WlanError as e:
            assert e.error_code == 0xff87 or e.error_code == 0xd2
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=ssl_server.interfaces.ssl,
                                                      server_port=port)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")

        check_td1.wait_for_exit(True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 2, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_wifi_sdk_error_code_check_when_certificate_loaded_in_same_index_C19656(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                       ble_client, ssl_server,
                                                                       wifi_client, logger, cert1, cert2, cert3, sl_collections):
    """
    Verify whether device is throwing error or not when trying to load certificate if certificate is already loaded and connected to server(TC_2)
    """
    try:
        logger.info(f"test_sdk_error_code_check_when_certificate_loaded_in_same_index_C19656")

        check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=20)
        check_td1.start()
        time.sleep(2)

        device_ip = join_ap(wifi_dut, wifi_access_point)

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']

        #
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]

        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, load_cert1, load_cert2)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        logger.info(f"Socket_id received{result_load_certificate}")
        #
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")

        try:
            wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                         cert_index=1)
        except WlanError as e:
            if e.error_code == 0x005d:
                logger.info("error_code is raised")
                assert e.error_code == 0x005d

        for socket in result_load_certificate:
            logger.info(f"Closing socket{socket}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket)

        #
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")
        #
        check_td1.wait_for_exit(True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 2, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_wifi_sdk_BLE_connectivity_data_tx_after_loadcert0_loadcert1_C19654(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   ble_client, ssl_server,
                                                                   wifi_client, logger, cert1, cert2, sl_collections):
    """
    Verify whether we are able to load certificates and connect to secure server in all 2 indexes after module initialization when enable and connect both WLAN and BLE interfaces
    """
    try:
        logger.info(f"test_sdk_BLE_connectivity_data_tx_after_loadcert0_loadcert1_C19654")
        check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=20)
        check_td1.start()
        time.sleep(2)
        device_ip = join_ap(wifi_dut, wifi_access_point)

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        # open/aws , index, port , cert
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, load_cert1, load_cert2)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        for socket in result_load_certificate:
            wifi_dut.interfaces.wifi.bsdSockClose(socket)

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")

        check_td1.wait_for_exit(True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 1, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_wifi_sdk_load_cert_with_wlan_ble_in_connected_state_C19651(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                           net_perf_client, ssl_server,
                                                           wifi_client, logger, cert1, sl_collections):
    """
    Verify whether we are able to load certificates and connect to secure server after module initialization when enable and connect both WLAN and BLE interfaces_TC_2
    """
    try:
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        data1 = "VzwQ"
        ping_count = 10
        ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        bt_local_name = "test_C19651"
        logger.info("configuring bd local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name)

        logger.info("fetching bd local name....")
        bd_local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger.info(f"bd local name is : {bd_local_name}")

        logger.info("start ble on DUT")
        ble_dut_addr = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_addr is not None, "Unable to get ble_dut_address"

        logger.info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        logger.info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        logger.info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        logger.info("Start ble advertising on DUT")
        # 256(0x100), 512(0x200), 7(0x07)
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7)

        logger.info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)

        ble_client_addr = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_addr)
        assert ble_client_addr is not None, "ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger.info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 200}

        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_addr,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        logger.info("BLE Connection success")
        time.sleep(2)

        logger.info("Configuring remote device to receive notifications from DUT")
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        services, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=services,
                                                                                               service_uid=service_uid,
                                                                                               char_uid=char_uid)
        assert char_path is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger.info("Subscribing to notifications on ble_client")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)

        logger.info("Sending notifications from DUT")

        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        wifi_dut.interfaces.wifi.ble_notify_value()

        # read value - Notifications not enabled
        result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        assert result == data1

        device_ip = join_ap(wifi_dut, wifi_access_point)

        load_cert1 = ["open", 0, port1, cert1]
        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, load_cert1)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        logger.info(f"Loading certificate{result_load_certificate}")

        logger.info("Get ble device state")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "Ble device is not connected"
        logger.info(" Connected to the BLE device ")

        wifi_dut.interfaces.wifi.bsdSockClose(0)
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 5, "stack_len": 2048}, }})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_wifi_sdk_BLE_connectivity_data_tx_after_loadcert0_C19655(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                         ssl_server,
                                                         wifi_client, logger, cert1, cert2, sl_collections):
    """
    Verify the BLE connectivity and WLAN data transfer in index0 after loading the certificate in index1
    """
    try:
        logger.info(f"test_sdk_BLE_connectivity_data_tx_after_loadcert0_C19655")
        ping_count = 10
        check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=15)
        check_td1.start()
        time.sleep(2)
        device_ip = join_ap(wifi_dut, wifi_access_point)

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, load_cert1)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        logger.info(f"LOAD_CERTIFICATE{result_load_certificate}")
        data = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate, send_count=2)
        data.start()
        data.wait_for_exit(True)

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")

        result_load_certificate1 = load_certificates_thread(wifi_dut, ssl_server, load_cert2)
        result_load_certificate.start()
        result_load_certificate.wait_for_exit(True)
        logger.info(f"LOAD_CERTIFICATE{result_load_certificate1}")
        check_td2 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate1, send_count=25)
        check_td2.start()

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected
        logger.info(" Connected to the BLE device ")

        check_td1.wait_for_exit(True)
        check_td2.wait_for_exit(True)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
@pytest.mark.skip()
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        # "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={"thread_config": {"wifi": {"count": 2, "stack_len": 2048}, }})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1}
)

@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_concurrent_mode_C19647(firmware_loader, wifi_dut, wifi_access_point, wifi_client, ssl_server, cert1, logger, sl_collections):
    """Verify the AP behavior and connected STA data transfer when we do load certificate in concurrent mode
    """
    try:
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        bytes_sent = (pkt_count * buffer_length)
        #DUT as STA
        logger.info("join AP")
        ping_count = 10
        wifi_dut.interfaces.wifi.scan(ssid=None)
        mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
        status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger.info(f"wifi_join status: {status}")
        ip_fail = 1
        for count in range(3):
            try:
                device_ip = wifi_dut.interfaces.wifi.start_ip()
                ip_fail = 0
                break
            except:
                time.sleep(5)
                logger.info(f"Retry_count:{count}")
        assert ip_fail == 0, "Getting IP failed"
        wifi_dut.interfaces.wifi.ping(device_ip, ping_size=ping_count)
        ##############DUT as AP
        for i in range(3):
            try:
                wifi_dut.interfaces.wifi.start_ap()
                break
            except:
                logger.info(f"Could not start ap")
        wifi_client.interfaces.wifi.join()
        device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip
        wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
        status = ping(wifi_client_ip, ping_count)
        assert status == 1
        logger.info("dut ap mode ip: " + device_ip_dut_as_ap)
        logger.info("wifi client ip: " + str(wifi_client_ip))

        load_cert1 = ["open", 0, port1, cert1]
        check_td1 = load_certificates_thread(wifi_dut, ssl_server, load_cert1)
        check_td1.start()
        time.sleep(1)
        # for i in range(2):
        wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
        status = ping(wifi_client_ip, ping_count)
        assert status == 1
        check_td1.wait_for_exit(True)
        result_load_certificate = check_td1.return_value

        check_td2 = data_tx_rx_pkt_thread(wifi_dut, ssl_server, result_load_certificate, pkt_count, buffer_length, bytes_sent, count=3)
        check_td2.start()
        time.sleep(1)

        wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
        status = ping(wifi_client_ip, ping_count)
        assert status == 1

        time.sleep(5)
        wifi_dut.interfaces.wifi.bsdSockClose(0)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)