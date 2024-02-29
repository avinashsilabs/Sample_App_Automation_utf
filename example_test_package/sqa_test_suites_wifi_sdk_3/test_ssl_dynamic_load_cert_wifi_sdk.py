import re
import time
import pytest
import string
import random
import threading
from random import randint
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.utils import get_tls_certificate_dir
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.sl_status import SLStatus
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
    Si91xModuleType
)

lock = threading.Lock()


def logger():
    return get_logger(__name__)


def text_generator(size=100):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(size))


class BleFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_dut_address=None, duration=60):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.char_path = None
        self.add_service = True
        self.duration = duration

    def ble_slave_connection(self, data_transfer=True, disconnect=False, wait_time=5):

        logger().info("******************** start ble in dut ********************")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, "Failed to initialize ble in dut"
        self.ble_dut_address = ble_dut_address
        if data_transfer:
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F)
        logger().info(" ******************** start ble_advertising in dut ********************")
        self.wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(5)
        logger().info("******************** start scanning for DUT from remote ble device ********************")
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, "Failed to initiate start scan in remote device"
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            if (ble_dut_address in found_devices and
                    found_devices[ble_dut_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data):
                device_found = True
                break
        self.ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "Failed to get DUT-BLE from remote device scan list"
        logger().info("******************** Initiating ble connection from remote ble device ********************")
        self.ble_client.interfaces.bluetooth.connect(ble_dut_address, min_conn_interval=40, max_conn_interval=40,
                                                     conn_latency=0, supervision_timeout=2000)
        time.sleep(wait_time)
        self.check_connection_status_on_dut()
        self.check_connection_status_on_raspi()

        if disconnect:
            logger().info("******************** Initiating ble disconnect from remote ble device ********************")
            self.ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
            self.ble_client.interfaces.bluetooth.close()

    def check_connection_status_on_dut(self):
        logger().info("******************** Checking connection status of BLE from DUT ********************")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        logger().info("******************** DUT is connected to remote ble device ********************")

    def check_connection_status_on_raspi(self):
        logger().info("******************** Checking connection status of BLE from remote device ********************")
        status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
        logger().info(f"Connection status in remote device '{self.ble_client.name}' is:{status}")
        assert status, f"Remote device '{self.ble_client.name}' is not connected to DUT"
        logger().info("******************** Remote ble device is connected to DUT ********************")

    def add_char_service(self):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        services, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(services) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"
        self.char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=services, service_uid=service_uid, char_uid=char_uid)
        assert self.char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=self.char_path)
        logger().info("******************** Remote ble device is subscribing to notification ********************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=char_uid)
        self.add_service = False
        time.sleep(5)

    def ble_data_transfer(self, check_connection=False, wait_time=5):
        if check_connection:
            self.check_connection_status_on_dut()
            self.check_connection_status_on_raspi()
        if self.add_service:
            self.add_char_service()
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        sw = Stopwatch()
        while sw.elapsed_sec <= self.duration:
            data = text_generator(15)
            if not lock.locked():
                with lock:
                    logger().info(f"******************** DUT-BLE is sending data ********************\ndata: '{data}'")
                    self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                    self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data)
                    self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                time.sleep(wait_time)
                logger().info("******************** Validating received data in remote ble device ********************")
                notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                assert notifications, "Failed to receive data in remote ble device"
                logger().info(f"Remote device received data: {notifications[-1]}")
                assert len(notifications) > 0, "Remote device failed to receive data"
                assert len(notifications[-1]) == len(data), "Received data is not matched at remote device"

    def unsubscribe_notification(self):
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        logger().info("******************** Remote ble device is unsubscribing from notification ********************")
        self.ble_client.interfaces.bluetooth.close()
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()

    def ble_disconnect_from_raspi(self):
        logger().info("******************** Initiating ble disconnect from Raspi ********************")
        self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)

    def run(self):
        self.ble_data_transfer()
        self.unsubscribe_notification()


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
                sw = Stopwatch()
                while sw.elapsed_sec <= 180:
                    if not lock.locked():
                        with lock:
                            time.sleep(1)
                            logger().info(f"Certificate Loading at index --> {index}")
                            self.wifi_dut.interfaces.wifi.set_ssl_certificate(
                                str(get_tls_certificate_dir().joinpath(element[3][0])),
                                Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                cert_index=index)
                        break

                local_port = randint(5001, 20000)
                logger().info(f"SSL start server on port {port}")
                self.ssl_server.interfaces.ssl.start_server(port=port, server_cert=element[3][1],
                                                            server_key=element[3][2])
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
                sock = self.wifi_dut.interfaces.wifi.socket()
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP",
                                                              option_val="tls_1_2")
                self.wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=index)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.device_ip,
                                                   server_port=local_port,
                                                   timeout=15)
                logger().info(f"DUT with sock id {sock} connecting to server with port number:{port}")
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port)
                list_sock.append(sock)

        logger().info(f"APPENDING INTO LIST RESULT{list_sock}")
        return list_sock


class data_tx_rx_thread(ThreadBase):
    def __init__(self, wifi_dut, ssl_server, result_load_certificate, send_count, sleep_time: float = 5):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.result_load_certificate = result_load_certificate
        self.send_count = send_count
        self.sleep_time = sleep_time

    def run(self):

        for element in self.result_load_certificate:
            for count in range(self.send_count):
                if not lock.locked():
                    with lock:
                        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                        logger().info(f"Data Sent :{data_sent}  on socket_id {element}")
                        self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=element, data=data_sent)
                    data_receive = self.ssl_server.interfaces.ssl.data_recv_content(element + 1, len(data_sent))
                    logger().info(f"Data received on remote socket opened is {data_receive}")
                    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                    logger().info("Data sent by DUT and received on server is matching")
                time.sleep(self.sleep_time)


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
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE, cert_index=0)

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
        assert retrial == 1, "Connection to socket failed"
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
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
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
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, power_save=False,
                                                                 ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, ping_after_ps=False)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        for cert_index in range(0, 3):
            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                         cert_index=cert_index)

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

            # Enable ssl option for socket opened
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
def test_wifi_sdk_connection_and_transfer_of_index0_index1_when_trying_loadcert_index2_TC19642(wifi_sniffer,
                                                                                               wifi_access_point,
                                                                                               wifi_dut, ssl_server,
                                                                                               logger,
                                                                                               cert1,
                                                                                               cert2, cert3,
                                                                                               sl_collections):
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
def test_wifi_sdk_connection_and_transfer_of_index0_index2_when_trying_loadcert_index1_TC19648(wifi_sniffer,
                                                                                               wifi_access_point,
                                                                                               wifi_dut, ssl_server,
                                                                                               logger,
                                                                                               cert1,
                                                                                               cert2, cert3,
                                                                                               sl_collections):
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
                       wifi=["close_socket", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_socket_connection_dataTX_enable_deep_sleep_base_powersave_C19650(wifi_sniffer, wifi_dut,
                                                                                       wifi_access_point,
                                                                                       ssl_server, logger, cert1, cert2,
                                                                                       cert3, sl_collections):
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
        #
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        # open/aws , index, port , cert
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        load_cert3 = ["open", 2, port3, cert3]

        result_load_certificate = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert2,
                                                           load_cert3)
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
                            domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", query_timeout=120000,
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
                            domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", query_timeout=120000,
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                wifi_dut.interfaces.wifi.set_ssl_certificate(
                    str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                    Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                    cert_index=cert_index)

            wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("start_field.pem")),
                                                         Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                         Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                         cert_index=2)

            wifi_dut.interfaces.wifi.set_ssl_certificate(
                str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
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
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                              server_port=socket_port)
                else:
                    for retry_count in range(1, 3):
                        aws_connection = 1
                        try:
                            result = wifi_dut.interfaces.wifi.dns_get(
                                domain_name="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", query_timeout=120000,
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
                list_of_sock_id = [0, 1]
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
def test_thread_wifi_sdk_connection_and_transfer_of_index1_index2_when_trying_loadcert_index0_TC19649(wifi_sniffer,
                                                                                                      wifi_access_point,
                                                                                                      wifi_dut,
                                                                                                      ssl_server,
                                                                                                      logger,
                                                                                                      cert1,
                                                                                                      cert2, cert3,
                                                                                                      sl_collections):
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


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2',
        'channel': 11,
        'standard': '11n'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C19647",
        "passphrase": "Automation123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.parametrize("cert1", [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                    "mosquitto-utf.silabs.com.key.pem")])
def test_wifi_sdk_ssl_dynamic_load_cert_in_concurrent_mode_c19647(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                  wifi_client, ssl_server, logger, sl_collections,
                                                                  request, cert1, sniffer_filter):
    """
    Verify the AP behavior and connected STA data transfer when we do load certificate in concurrent mode
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger.info("********** Starting DUT as an AP *********")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C19647", security="WPA2", psk="Automation123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        logger.info("********** DUT as AP is started **********")
        logger.info("**********  Connecting Raspi-STA to DUT-AP **********")
        wifi_client.interfaces.wifi.join()
        wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address(network_interface="wlan0")
        dut_ap_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger.info(f"RASPI-STA IP: '{wifi_client_ip}'")
        logger.info(f"DUT-AP IP: '{dut_ap_ip}'")

        load_cert = ["open", 0, port1, cert1]
        ping_thread = Thread(target=ping, args=(dut_ap_ip, 20))
        certs_load = load_certificates_thread(wifi_dut, ssl_server, dut_sta_ip, load_cert)
        logger.info("************** Pinging to DUT-AP from RASPI-STA **************")
        ping_thread.start()
        time.sleep(2)
        logger.info("************** Loading Certificate in DUT Parallely **************")
        certs_load.start()
        ping_thread.join()
        certs_load.wait_for_exit(True)
        sock_id = certs_load.return_value

        ping_thread = Thread(target=ping, args=(dut_ap_ip, 30))
        trf_thread = data_tx_rx_thread(wifi_dut, ssl_server, sock_id, send_count=30, sleep_time=1)
        logger.info("************** Pinging to DUT-AP from RASPI-STA **************")
        ping_thread.start()
        logger.info("************** Initiating SSL-TX from DUT **************")
        trf_thread.start()
        time.sleep(5)
        ping_thread.join()
        trf_thread.wait_for_exit(True)

        logger.info(f"Closing socket_id->{sock_id[-1]}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id[-1])
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1, cert2", [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"],
                                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"])])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_error_code_check_when_cert_loaded_in_same_index_c19656(wifi_sniffer, wifi_dut, sniffer_filter, cert1,
                                                                         ble_client, ssl_server, logger, request, cert2,
                                                                         sl_collections, wifi_access_point):
    """
    Verify whether device is throwing error or not when trying to load certificate if certificate is already loaded and connected to server(TC_2)
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client, duration=90)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert2)
        load_certs_thread.start()

        load_certs_thread.wait_for_exit(True)
        ble_obj.check_connection_status_on_raspi()
        ble_obj.check_connection_status_on_dut()

        sw = Stopwatch()
        error_code = None
        while sw.elapsed_sec <= 30:
            if not lock.locked():
                with lock:
                    try:
                        logger.info(
                            "\n\n**************** Loading Certificate at index pre-loaded index 1 ****************")
                        wifi_dut.interfaces.wifi.set_ssl_certificate(
                            get_tls_certificate_dir().joinpath("ca-chain.cert.pem"),
                            "ca_cert", "tls_server", 1)
                    except Exception as err:
                        logger.info(f"*********** Error Observed ***********\n {err}")
                        error_match = re.search("status:(.*)", str(err))
                        if error_match:
                            error_code = error_match.group()
                            logger.info(f"error_code: {error_code}")
                break
        assert error_code, ("DUT did not send error code when trying to load certificate at index which is already "
                            "loaded, which is not expected")
        logger.info(f"DUT sent error code when trying to load certificate at index which is already loaded with "
                    f"certificate, which is expected")
        ble_thread.wait_for_exit(True)

        ble_obj.ble_disconnect_from_raspi()
        socks = load_certs_thread.return_value
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1", [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                    "mosquitto-utf.silabs.com.key.pem")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_load_cert_with_wlan_ble_in_connected_state_with_ps_c19651(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                            ble_client, request, ssl_server, logger,
                                                                            sniffer_filter, cert1, sl_collections):
    """
    Verify whether we are able to load certificates and connect to secure server after module initialization when enable
    and connect both WLAN and BLE interfaces_TC_2
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        load_cert1 = ["open", 0, port1, cert1]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1)
        load_certs_thread.start()
        load_certs_thread.wait_for_exit(True)
        ble_thread.wait_for_exit(True)
        ble_obj.check_connection_status_on_dut()
        ble_obj.check_connection_status_on_raspi()

        ble_obj.ble_disconnect_from_raspi()
        socks = load_certs_thread.return_value
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1", [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                    "mosquitto-utf.silabs.com.key.pem")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_load_cert_with_wlan_ble_in_connected_state_without_ps_c19652(wifi_sniffer, wifi_dut, sniffer_filter,
                                                                               sl_collections, wifi_access_point, cert1,
                                                                               ble_client, request, ssl_server, logger):
    """
    Verify whether DUT is able to load certificate with WLAN and BLE in connected state without power save
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        load_cert1 = ["open", 0, port1, cert1]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, power_save=False,
                                                         associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1)
        load_certs_thread.start()
        load_certs_thread.wait_for_exit(True)
        ble_thread.wait_for_exit(True)

        ble_obj.check_connection_status_on_dut()
        ble_obj.check_connection_status_on_raspi()

        ble_obj.ble_disconnect_from_raspi()
        socks = load_certs_thread.return_value
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1", [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                    "mosquitto-utf.silabs.com.key.pem")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_ble_connectivity_data_tx_after_load_cert_c19653(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                                  ssl_server, sniffer_filter, logger, cert1, request,
                                                                  sl_collections):
    """
    Verify the BLE connectivity and data transfer after loading the certificate and connect to SSL server
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        load_cert1 = ["open", 0, port1, cert1]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(3)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1)
        load_certs_thread.start()
        load_certs_thread.wait_for_exit(True)
        time.sleep(3)
        ble_obj.check_connection_status_on_dut()
        ble_obj.check_connection_status_on_raspi()
        ble_thread.wait_for_exit(True)

        ble_obj.ble_disconnect_from_raspi()
        socks = load_certs_thread.return_value
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1, cert2", [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"],
                                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"])])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_ble_connection_data_tx_after_loading_cert0_cert1_c19654(sl_collections, sniffer_filter, cert1, cert2,
                                                                          wifi_sniffer, wifi_dut, wifi_access_point,
                                                                          ssl_server, request, logger, ble_client):
    """
    Verify whether we are able to load certificates and connect to secure server in all 2 indexes after module
    initialization when enable and connect both WLAN and BLE interfaces.
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client, duration=90)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1, load_cert2)
        load_certs_thread.start()
        load_certs_thread.wait_for_exit(True)
        time.sleep(3)
        ble_obj.check_connection_status_on_dut()
        ble_obj.check_connection_status_on_raspi()
        ble_thread.wait_for_exit(True)

        ble_obj.ble_disconnect_from_raspi()
        socks = load_certs_thread.return_value
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC_AE_COEX,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1, cert2", [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"],
                                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                            "mosquitto-utf.silabs.com.key.pem"])])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_ble_connectivity_data_tx_after_load_cert0_c19655(wifi_sniffer, wifi_dut, wifi_access_point, logger,
                                                                   ble_client, ssl_server, request, sniffer_filter,
                                                                   cert1, cert2, sl_collections):
    """
    Verify the BLE connectivity and WLAN data transfer in index0 after loading the certificate in index1
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        load_cert1 = ["open", 0, port1, cert1]
        load_cert2 = ["open", 1, port2, cert2]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client, duration=100)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        socks = []
        for i in range(1, 3):
            load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, eval(f"load_cert{i}"))
            load_certs_thread.start()
            load_certs_thread.wait_for_exit(True)
            sock_id = load_certs_thread.return_value
            socks.append(sock_id[-1])
            time.sleep(1)
            ble_obj.check_connection_status_on_raspi()
            ble_obj.check_connection_status_on_dut()
            trf_thread = data_tx_rx_thread(wifi_dut, ssl_server, sock_id, send_count=15, sleep_time=1)
            logger.info("************** Initiating SSL-TX from DUT **************")
            trf_thread.start()
            if i == 2:
                ble_thread.wait_for_exit(True)
            trf_thread.wait_for_exit(True)

        ble_obj.ble_disconnect_from_raspi()
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE |
                        Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 2048}}
    }
)
@pytest.mark.parametrize("cert1", [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                                    "mosquitto-utf.silabs.com.key.pem")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect", "clear_certs"])
def test_wifi_sdk_wlan_ble_connection_load_cert_time_gt_200ms_c19657(wifi_sniffer, wifi_dut, wifi_access_point, logger,
                                                                     ble_client, ssl_server, request, sniffer_filter,
                                                                     cert1, sl_collections):
    """
    Verify BLE and WLAN data transfer while loading the certificate.
    (Note: Loading certificate should take more than 200ms)
    """
    try:
        capture_filename = request.node.name
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        load_cert1 = ["open", 0, port1, cert1]
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        ble_thread = ble_obj = BleFunctionality(wifi_dut, ble_client, duration=75)
        ble_obj.ble_slave_connection()
        ble_thread.start()
        time.sleep(10)
        with lock:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, retry_count=3, associated=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f"AP BSSID : {ap_bssid}")

        load_certs_thread = load_certificates_thread(wifi_dut, ssl_server, device_ip, load_cert1)
        load_certs_thread.start()
        load_certs_thread.wait_for_exit(True)
        socks = load_certs_thread.return_value
        trf_thread = data_tx_rx_thread(wifi_dut, ssl_server, socks, send_count=30, sleep_time=1)
        logger.info("************** Initiating SSL-TX from DUT **************")
        trf_thread.start()
        time.sleep(10)
        ble_obj.check_connection_status_on_raspi()
        ble_obj.check_connection_status_on_dut()

        with lock:
            with open(str(get_tls_certificate_dir().joinpath(cert1[0]))) as f:
                cert_contents = f.read()
            size = len(cert_contents)
            buffer_size = (512 * (int(size / 512))) + 512
            address = wifi_dut.interfaces.wifi.allocate_memory(size=buffer_size)
            wifi_dut.interfaces.wifi.load_memory(address, size=size, write_content=cert_contents)
            with TimeMeasurer() as t:
                logger.info("************** Loading certificate ca_cert at index --> 1 **************")
                command = f'wifi.load_cert {address} -c ca_cert -i tls_server -n 1'
                status, data = wifi_dut.interfaces.wifi.issue_command(command, 30)
            wifi_dut.interfaces.wifi.verify_status(status, SLStatus.SL_STATUS_OK)
            logger.info(f"************** Time taken to load certificate is --> '{t.duration}' seconds **************")
            assert t.duration > 0.2, "Time taken to load certificate is less than 200ms"
            wifi_dut.interfaces.wifi.memory_free(address)
            time.sleep(3)
            ble_obj.check_connection_status_on_dut()
            ble_obj.check_connection_status_on_raspi()
        ble_thread.wait_for_exit(True)
        trf_thread.wait_for_exit(True)

        ble_obj.ble_disconnect_from_raspi()
        for sock_id in socks:
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
