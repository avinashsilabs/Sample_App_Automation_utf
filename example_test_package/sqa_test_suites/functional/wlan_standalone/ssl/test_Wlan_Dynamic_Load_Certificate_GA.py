import threading
import time
from threading import Thread
from utf.utils.thread_base import ThreadBase
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    SocketOptions,
    DeviceConstants,
)
import string
import random
import time
from threading import Thread
from utf.utils.time_measurer import TimeMeasurer
import math
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEConnectError
from utf.interfaces.wifi import WlanError
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from random import randint


def logger():
    return get_logger(__name__)

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

class ble_data_transfer_thread(ThreadBase):
    def __init__(self,wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client


    def run(self):
        data = []
        for i in range(20):
            data.append(text_generator(size=4))
        logger().info(f"INTO EXECUTION FOR THREAD2")
        self.ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        bt_local_name = "rs9116_test_C20309"
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
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7)

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
        assert (found_devices[self.wifi_dut.interfaces.wifi.ble_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data)
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
        bus = self.ble_client.interfaces.bluetooth.bus
        services, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus, services=services,
                                                                                               service_uid=service_uid,
                                                                                               char_uid=char_uid)
        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger().info("Subscribing to notifications on ble_client")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

        logger().info("Sending notifications from DUT")
        for i in range(20):
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[i])
            self.wifi_dut.interfaces.wifi.ble_notify_value()
            time.sleep(2)

        logger().info("Validating received notifications on ble_client")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications: {notifications}")
        notification_len = len(notifications)
        for i in range(0, notification_len):
            assert notifications[i] == data[i], "Received wrong data in ble_client"


def data_tx_rx(wifi_dut, ssl_server, result_load_certificate, send_count):
    logger().info(f"{result_load_certificate}")
    for element in result_load_certificate:
        for iter in range(0, send_count):
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            logger().info(f"Date Sent :{data_sent} and lenght of the data {data_length}")

            wifi_dut.interfaces.wifi.send_data(element, data_length, data_sent)
            # server_socket_no = result_load_certificate[i] + 1
            server_socket_no = element + 1
            logger().info(f"data sent server_socket_no {server_socket_no}")
            # # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
            logger().info("Data sent by DUT and received on server is matching")
    return True



def load_certificates(wifi_dut, ssl_server, *lst: list):
    logger().info("THREAD EXEC")
    list_sock = []
    for i in lst:
        index = i[1]
        if i[0] == "open":
            port = i[2]
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(i[3][0])),
                                                     cert_index=index,
                                                     )
            time.sleep(2)
            wifi_dut.interfaces.wifi.start_ip()
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

            ssl_server.interfaces.ssl.start_server(port=port, server_cert=i[3][1], server_key=i[3][2])

            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

            list_sock.append(sock)
            logger().info(f"List sockets{list_sock}")
            # Enable cert index 0 for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   eval("SocketOptions.CERT_INDEX" + str(index)))

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
            # # if
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port)

            # list_sock[index] = list_sock.append(sock)
    logger().info(f"APPENDING INTO LIST RESULT{list_sock}")
    return list_sock


class load_certificates_thread(ThreadBase):
    def __init__(self,wifi_dut, ssl_server, *lst: list):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.lst = lst

    def run(self):
        #load_certificates(self.wifi_dut, self.ssl_server, self.lst)
        logger().info("THREAD EXEC")
        list_sock = []
        for element in self.lst:
            index = element[1]
            if element[0] == "open":
                port = element[2]
                self.wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(element[3][0])),
                                                         cert_index=index,
                                                         )
                self.wifi_dut.interfaces.wifi.start_ip()
                self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
                self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

                self.ssl_server.interfaces.ssl.start_server(port=port, server_cert=element[3][1], server_key=element[3][2])

                sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

                list_sock.append(sock)
                logger().info(f"List sockets{list_sock}")
                # Enable cert index 0 for socket opened
                self.wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       eval("SocketOptions.CERT_INDEX" + str(index)))

                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
                # # if
                self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.ssl_server.interfaces.ssl, server_port=port)

                # list_sock[index] = list_sock.append(sock)
        logger().info(f"APPENDING INTO LIST RESULT{list_sock}")
        return list_sock

class data_tx_rx_thread(ThreadBase):
    def __init__(self,wifi_dut, ssl_server, result_load_certificate, send_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.result_load_certificate = result_load_certificate
        self.send_count = send_count

    def run(self):

        for element in self.result_load_certificate:
            for iter in range(0,   self.send_count):
                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                logger().info(f"Date Sent :{data_sent} and lenght of the data {data_length}")

                self.wifi_dut.interfaces.wifi.send_data(element, data_length, data_sent)

                # server_socket_no = result_load_certificate[i] + 1
                server_socket_no = element + 1
                logger().info(f"data sent server_socket_no {server_socket_no}")
                # # SSL server receives the data over ssl socket
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                logger().info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                logger().info("Data sent by DUT and received on server is matching")
                time.sleep(5)

@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT ,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 ,
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
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connection_and_transfer_of_index0_index1_when_trying_loadcert_index2_TC19642(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1,
                                            cert2, cert3):

    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1,load_cert2)
    check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate, send_count=5)
    check_td2 = load_certificates_thread(wifi_dut, ssl_server, load_cert3)
    check_td1.start()
    time.sleep(1)
    check_td2.start()
    time.sleep(1)
    check_td2.wait_for_exit(True)
    list_of_soc_id = check_td2.return_value
    logger.info(f"list of soc id  '{list_of_soc_id}'")
    logger.info(f"list of sock if {type(list_of_soc_id)}")
    data_tx_rx(wifi_dut, ssl_server, list_of_soc_id, send_count=2)
    check_td1.wait_for_exit(True)
    logger.info(f"results of sock_id{result_load_certificate}{list_of_soc_id}")
    result_load_certificate.extend(list_of_soc_id)
    for socket in result_load_certificate:
        logger.info(f"Closing socket{socket}")
        wifi_dut.interfaces.wifi.close_socket(socket)


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT ,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 ,
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
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connection_and_transfer_of_index0_index2_when_trying_loadcert_index1_TC19648(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1,
                                            cert2, cert3):

    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1,load_cert3)
    logger.info(f"resulteeee{result_load_certificate}")
    check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate,send_count=10)
    check_td2 = load_certificates_thread(wifi_dut, ssl_server, load_cert2)
    check_td1.start()
    time.sleep(1)
    check_td2.start()
    time.sleep(1)
    check_td2.wait_for_exit(True)
    list_of_soc_id = check_td2.return_value
    logger.info(f"list of soc id  '{list_of_soc_id}'")
    data_tx_rx(wifi_dut, ssl_server, list_of_soc_id, send_count=2)
    check_td1.wait_for_exit(True)
    logger.info(f"results of sock_id{result_load_certificate}{list_of_soc_id}")
    result_load_certificate.extend(list_of_soc_id)
    logger.info(f"results of sock_id{result_load_certificate}")
    for socket in result_load_certificate:
        logger.info(f"Closing socket{socket}")
        wifi_dut.interfaces.wifi.close_socket(socket)

@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT ,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_test_connection_and_transfer_of_index1_index2_when_trying_loadcert_index0_TC19649(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1,
                                            cert2, cert3):

    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert2,load_cert3)
    check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate,send_count=10)
    check_td2 = load_certificates_thread(wifi_dut, ssl_server, load_cert1)
    check_td1.start()
    time.sleep(1)
    check_td2.start()
    time.sleep(1)
    check_td2.wait_for_exit(True)
    list_of_soc_id = check_td2.return_value
    logger.info(f"list of soc id  '{list_of_soc_id}'")
    data_tx_rx(wifi_dut, ssl_server, list_of_soc_id, send_count=2)
    check_td1.wait_for_exit(True)
    logger.info(f"results of sock_id{result_load_certificate}{list_of_soc_id}")
    result_load_certificate.extend(list_of_soc_id)
    for socket in result_load_certificate:
        logger.info(f"Closing socket{socket}")
        wifi_dut.interfaces.wifi.close_socket(socket)


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_load_cert_with_wlan_ble_in_connected_state_C19652(wifi_sniffer, wifi_dut, wifi_access_point, ble_client, net_perf_client,ssl_server,
                                                             wifi_client ,logger, cert1):
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    data1 = "abcd"

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
    bus = ble_client.interfaces.bluetooth.bus
    services, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
    assert len(services) > 0, "Unable to fetch services"
    assert len(chars) > 0, "Unable to get characteristics list from ble_client"

    char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus, services=services,
                                                                                           service_uid=service_uid,
                                                                                           char_uid=char_uid)
    assert char is not None, "Unable to resolve custom service characteristic from ble_client"
    assert len(char_props) > 0, "Unable to get char_props"

    logger.info("Subscribing to notifications on ble_client")
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

    logger.info("Sending notifications from DUT")

    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
    wifi_dut.interfaces.wifi.ble_notify_value()

    # read value - Notifications not enabled
    result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
    assert result == data1

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    wifi_dut.interfaces.wifi.scan(ssid=None)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
    load_cert1 = ["open", 0, port1, cert1]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1)
    logger.info(f"Loading certificate{result_load_certificate}")

    wifi_dut.interfaces.wifi.close_socket(0)


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_BLE_connectivity_data_tx_after_loadcert_C19653(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,ssl_server,
                                                             wifi_client, logger, cert1):
    logger.info(f"19653")
    check_td1 = ble_data_transfer_thread(wifi_dut, ble_client)
    check_td1.start()

    wifi_dut.interfaces.wifi.scan(ssid=None)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"Device mac address: {dut_mac_address}")

    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1)
    wifi_dut.interfaces.wifi.close_socket(0)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    check_td1.wait_for_exit(True)







