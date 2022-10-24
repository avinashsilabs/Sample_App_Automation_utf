# Test author: Vinod.G
# Test suite: WLAN_Dynamic_Load_Certificate_GA
import time
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
    RS9116Band,
    RS9116OperatingMode,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    SocketOptions,
    DeviceConstants,
    )
from utf.interfaces.wifi import WlanError
from utf.utils import get_tls_certificate_dir
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
import threading
import time
from threading import Thread
from utf.utils.thread_base import ThreadBase
from random import randint
import string
import random

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
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
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
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
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address

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
        bus = self.ble_client.interfaces.bluetooth.bus
        services, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                                    services=services,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger().info("Subscribing to notifications on ble_client")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
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


def data_tx_rx(wifi_dut, ssl_server, result_load_certificate, send_count):
    logger().info(f"{result_load_certificate}")
    for element in result_load_certificate:
        for iter in range(0, send_count):
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            logger().info(f"Date Sent :{data_sent} and lenght of the data {data_length}")

            wifi_dut.interfaces.wifi.send_data(element, data_length, data_sent)
            server_socket_no = element + 1
            logger().info(f"data sent server_socket_no {server_socket_no}")
            # # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
            logger().info("Data sent by DUT and received on server is matching")
    return True


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
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    time.sleep(wait_time)
    logger().info(f"wifi_join status: {status}")
    ip_fail = 1
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.start_ip(timeout=25)
            ip_fail = 0
            break
        except:
            time.sleep(5)
            logger().info(f"Retry_count:{count}")
    assert ip_fail == 0, "Getting IP failed"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    return device_ip


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

            wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
            # # if
            connect = 1
            for count in range(3):
                try:
                    logger().info("ssl connection try")
                    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port)
                    connect = 0
                    break
                except:
                    time.sleep(5)
                    logger().info(f"Retry_count:{count}")
            assert connect == 0

    logger().info(f"APPENDING INTO LIST RESULT{list_sock}")
    return list_sock


class load_certificates_thread(ThreadBase):
    def __init__(self, wifi_dut, ssl_server, *lst: list):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.lst = lst

    def run(self):
        # load_certificates(self.wifi_dut, self.ssl_server, self.lst)
        logger().info("THREAD EXEC")
        list_sock = []
        for element in self.lst:
            index = element[1]
            if element[0] == "open":
                port = element[2]
                self.wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                                  str(get_tls_certificate_dir().joinpath(
                                                                      element[3][0])),
                                                                  cert_index=index,
                                                                  )
                self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
                self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
                self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
                device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

                self.ssl_server.interfaces.ssl.start_server(port=port, server_cert=element[3][1],
                                                            server_key=element[3][2])

                sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET,
                                                                SocketOptions.SO_SSL_ENABLE,
                                                                SocketOptions.SSL_ENABLE)

                list_sock.append(sock)
                logger().info(f"List sockets{list_sock}")
                # Enable cert index 0 for socket opened
                self.wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET,
                                                                SocketOptions.SO_CERT_INDEX,
                                                                eval("SocketOptions.CERT_INDEX" + str(index)))

                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
                # # if
                connect = 1
                for count in range(3):
                    try:
                        logger().info("ssl connection try")
                        self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.ssl_server.interfaces.ssl, server_port=port)
                        connect = 0
                        break
                    except:
                        time.sleep(4)
                        logger().info(f"Retry_count:{count}")
                assert connect == 0

                # list_sock[index] = list_sock.append(sock)
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
                logger().info(f"Date Sent :{data_sent} and lenght of the data {data_length}")

                self.wifi_dut.interfaces.wifi.send_data(element, data_length, data_sent)
                server_socket_no = element + 1
                logger().info(f"data sent server_socket_no {server_socket_no}")
                # # SSL server receives the data over ssl socket
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                logger().info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                logger().info("Data sent by DUT and received on server is matching")
                time.sleep(5)



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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_cert_no_index_TC19638(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    logger.info(f"Sending data {data_sent} over socket_no->{sock}")
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    logger.info(f"Data received on remote socket opened is {data_receive}")
    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
    logger.info("Data sent by DUT and received on server is matching")

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
    result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    logger.info(f"Number of bytes sent by dut {result}")
    bytes_sent = result

    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                         f"not matched on socket {server_socket_no} "
    logger.info(
        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
    # Close socket 1
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")



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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_cert_socket_connected_state_TC19639(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    port1 = ssl_server.interfaces.ssl.config['device_port1']

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    with pytest.raises(WlanError) as exc_info:
        # The below API loads ca-cert into DUT
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
    assert ((exc_info.value.error_code == 0x5d) or (exc_info.value.error_code == 0x5e)), "observed wrong error code, " \
                                                                                         "expected is 0x5d or 0x5e "
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_new_cert_TC19640(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    logger.info(f"Sending data {data_sent} over socket_no->{sock}")
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    logger.info(f"Data received on remote socket opened is {data_receive}")
    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
    logger.info("Data sent by DUT and received on server is matching")

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
    result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    logger.info(f"Number of bytes sent by dut {result}")
    bytes_sent = result

    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                         f"not matched on socket {server_socket_no} "
    logger.info(
        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")

    logger.info(f"clear certificate type -> {RS9116CertificateType.SSLCACertificate}")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["start_field.pem", "client-certificate.crt",
                               "private-key.key"]

                              )
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_TC19641(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_dynamic_load_three_ssl_sockets_TC19641"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = 8883
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientCertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                 cert_index=2,
                                                 )
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                                 str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                 cert_index=2,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
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
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        if sock_count < 2:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        else:
            result = wifi_dut.interfaces.wifi.dns_get(4)
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            for retry_count in range(1, 4):
                try:
                    aws_connection = 1
                    logger.info("Connecting to AWS server")
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
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
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["start_field.pem", "client-certificate.crt",
                               "private-key.key"]

                              )
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_multiple_iterations_TC19643(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_dynamic_load_three_ssl_sockets_TC19643"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = 8883

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientCertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                 cert_index=2,
                                                 )
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                                 str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                 cert_index=2,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
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
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        if sock_count < 2:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        else:
            result = wifi_dut.interfaces.wifi.dns_get(4)
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            for retry_count in range(1, 4):
                try:
                    aws_connection = 1
                    logger.info("Connecting to AWS server")
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                    aws_connection = 0
                    break
                except:
                    logger.info(f"Connecting to the AWS server is failed on retry count -> {retry_count}")
                    time.sleep(1)
            if aws_connection:
                logger.info("Connecting to AWS server is failed")
                assert aws_connection == 0, "Connecting to AWS server is failed"

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 0")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 1")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=1
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 2")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=2
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLClientCertificate} at index 2")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLClientCertificate,
                                               cert_index=2
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLClientPrivateKey} at index 2")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                               cert_index=2
                                               )
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientCertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                 cert_index=2,
                                                 )
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                                 str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                 cert_index=2,
                                                 )

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["start_field.pem", "client-certificate.crt",
                               "private-key.key"]

                              )
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_load_certs_without_erasing_multiple_times_TC19644(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_load_certs_without_erasing_multiple_times_TC19644"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = 8883
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

    for iteration in range(1, 3):
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
        # The below API loads ca-cert into DUT at cert index 1
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                     cert_index=1,
                                                     )
        # The below API loads ca-cert into DUT at cert index 2
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientCertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                                     str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                     cert_index=2,
                                                     )
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0 in iteration {iteration}"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1 in iteration {iteration}"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2 in iteration {iteration}"
            logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected in iteration {iteration}")
            logger.info(
                f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API in iteration {iteration}")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1
            else:
                cert_index = SocketOptions.CERT_INDEX2
            logger.info(
                f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API in iteration {iteration}")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
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
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            if sock_count < 2:
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
            else:
                result = wifi_dut.interfaces.wifi.dns_get(4)
                logger.info(f"dns response is {result}")
                server_ip = result.split(b"\n")[1].split(b":")[1].decode()
                for retry_count in range(1, 4):
                    try:
                        aws_connection = 1
                        logger.info("Connecting to AWS server")
                        wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                        aws_connection = 0
                        break
                    except:
                        logger.info(f"Connecting to the AWS server is failed on retry count -> {retry_count}")
                        time.sleep(1)
                if aws_connection:
                    logger.info("Connecting to AWS server is failed")
                    assert aws_connection == 0, "Connecting to AWS server is failed"

        if iteration != 1:
            socket_no = [1, 2]
            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                socket_no = [1, 2]
                for socket in socket_no:
                    if ssl_server.interfaces.ssl.socket_connection_status(socket):
                        result = wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                        logger.info(f"Number of bytes sent by dut {result}")
                        bytes_sent = result
                        time.sleep(10)
                        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote " \
                                                             f"peer " \
                                                             f"not matched on socket {socket} in iteration {iteration} "
                        logger.info(
                            f"Number of bytes sent by DUT and received on the remote peer are matched on socket {socket} in iteration {iteration}")

                    else:
                        assert f"failed to connect on socket no {socket} in iteration {iteration}"

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count} in iteration {iteration}")
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count} in iteration {iteration} "
            logger.info(f"Successfully closed socket_id->{sock_count} in iteration {iteration}")

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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
def test_dynamic_load_powersave_not_enabled_TC19646(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
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
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
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
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")



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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
def test_dynamic_load_powersave_enabled_testcase14(
        wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    # The below API loads ca-cert into DUT at cert index 1
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                 cert_index=1,
                                                 )
    # The below API loads ca-cert into DUT at cert index 2
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                 cert_index=2,
                                                 )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

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

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)
    wifi_dut.interfaces.wifi.leave()


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
def test_dynamic_load_auto_join_TC19645(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, cert1, cert2, cert3, domain_name
        ):

        ping_count = 10
        capture_filename = "test_dynamic_load_auto_join_TC19645"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        bytes_sent = (pkt_count * buffer_length)
        result = wifi_dut.interfaces.wifi.version()
        logger.info(f"DUT firmware version: {result}")
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
        if scan_fail:
            logger.info(f"Scanning to the AP has failed")
            assert scan_fail == 0, "Scanning to the AP is failed"

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
            )

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
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
        if join_fail:
            logger.info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
                ip_fail = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        if ip_fail:
            logger.info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)


        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable(config=1)
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
        ping(device_ip, ping_count)


        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
        # The below API loads ca-cert into DUT at cert index 1
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                     cert_index=1,
                                                     )
        # #The below API loads ca-cert into DUT at cert index 2
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientCertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[1])),
                                                     cert_index=2,
                                                     )
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLClientPrivateKey,
                                                     str(get_tls_certificate_dir().joinpath(cert3[2])),
                                                     cert_index=2,
                                                     )

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode


        logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        ping(device_ip, ping_count)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
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
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # ssl socket opened in DUT connects to the server
            if sock_count < 2:
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
            else:
                result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                          "NULL")
                logger.info(f"dns response is {result}")
                server_ip = result.split(b"\n")[1].split(b":")[1].decode()

                for count in range(0, 2):
                    try:
                        wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                        break
                    except:
                        logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                        time.sleep(1)
                logger.info(f"Connection to AWS server on socket id->{sock} is SUCCESSFULon the count{count}")

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
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
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

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
def test_connection_and_transfer_of_index0_index1_when_trying_loadcert_index2_TC19642(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3):

    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1, load_cert2)
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

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
def test_connection_and_transfer_of_index0_index2_when_trying_loadcert_index1_TC19648(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3):

    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1, load_cert3)
    logger.info(f"resulteeee{result_load_certificate}")
    check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate, send_count=10)
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

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
def test_connection_and_transfer_of_index1_index2_when_trying_loadcert_index0_TC19649(wifi_sniffer, wifi_access_point,
                                                                                      wifi_dut, ssl_server, logger,
                                                                                      cert1,
                                                                                      cert2, cert3):

    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert2, load_cert3)
    check_td1 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate, send_count=10)
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


@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_load_cert_with_wlan_ble_in_connected_state_C19652(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                           net_perf_client, ssl_server,
                                                           wifi_client, logger, cert1):
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    data1 = "abcd"
    # ping_count = 10
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
    device_ip = join_ap(wifi_dut, wifi_access_point)

    load_cert1 = ["open", 0, port1, cert1]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1)
    logger.info(f"Loading certificate{result_load_certificate}")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    wifi_dut.interfaces.wifi.close_socket(0)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_BLE_connectivity_data_tx_after_loadcert0_C19653(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                         ssl_server,
                                                         wifi_client, logger, cert1):
    logger.info(f"19653")
    ping_count = 10
    check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=12)
    check_td1.start()
    time.sleep(2)
    device_ip = join_ap(wifi_dut, wifi_access_point)

    port = ssl_server.interfaces.ssl.config['device_port1']

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    ssl_server.interfaces.ssl.start_server(port=port, server_cert=cert1[1], server_key=cert1[2])

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
    # # if
    try:
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port)
    except WlanError as e:
        assert e.error_code == 0xff87 or e.error_code == 0xd2
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port)

    wifi_dut.interfaces.wifi.close_socket(sock)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    check_td1.wait_for_exit(True)


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_error_code_check_when_certificate_loaded_in_same_index_C19656(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                       ble_client, ssl_server,
                                                                       wifi_client, logger, cert1, cert2, cert3):
    logger.info(f"19656")

    check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=20)
    check_td1.start()
    time.sleep(2)

    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']

    #
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1, load_cert2)
    logger.info(f"Socket_id received{result_load_certificate}")
    #
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    try:
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                     cert_index=1,
                                                     )
    except WlanError as e:
        if e.error_code == 0x005d:
            logger.info("error_code is raised")
            assert e.error_code == 0x005d

    for socket in result_load_certificate:
        logger.info(f"Closing socket{socket}")
        wifi_dut.interfaces.wifi.close_socket(socket)

    #
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")
    #
    check_td1.wait_for_exit(True)


@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_BLE_connectivity_data_tx_after_loadcert0_loadcert1_C19654(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   ble_client, ssl_server,
                                                                   wifi_client, logger, cert1, cert2):
    logger.info(f"19654")
    check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=20)
    check_td1.start()
    time.sleep(2)
    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1, load_cert2)
    for socket in result_load_certificate:
        wifi_dut.interfaces.wifi.close_socket(socket)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    check_td1.wait_for_exit(True)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_load_cert_with_wlan_ble_in_connected_state_C19651(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                           net_perf_client, ssl_server,
                                                           wifi_client, logger, cert1):
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



    device_ip = join_ap(wifi_dut, wifi_access_point)

    load_cert1 = ["open", 0, port1, cert1]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1)
    logger.info(f"Loading certificate{result_load_certificate}")

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    wifi_dut.interfaces.wifi.close_socket(0)
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_disconnect"])
def test_BLE_connectivity_data_tx_after_loadcert0_C19655(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,
                                                         ssl_server,
                                                         wifi_client, logger, cert1, cert2):
    logger.info(f"19655")
    ping_count = 10
    check_td1 = ble_data_transfer_thread(wifi_dut, ble_client, count=15)
    check_td1.start()
    time.sleep(2)
    device_ip = join_ap(wifi_dut, wifi_access_point)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1)
    logger.info(f"LOAD_CERTIFICATE{result_load_certificate}")
    data_tx_rx(wifi_dut, ssl_server, result_load_certificate, send_count=2)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    result_load_certificate1 = load_certificates(wifi_dut, ssl_server, load_cert2)
    logger.info(f"LOAD_CERTIFICATE{result_load_certificate1}")
    check_td2 = data_tx_rx_thread(wifi_dut, ssl_server, result_load_certificate1, send_count=25)
    check_td2.start()

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected
    logger.info(" Connected to the BLE device ")

    check_td1.wait_for_exit(True)
    check_td2.wait_for_exit(True)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
         "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "close_socket"])
def test_ssl_socket_connection_dataTX_enable_deep_sleep_base_powersave_C19650(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                              ssl_server, logger, cert1, cert2, cert3):
    logger.info(f"19650")
    power_save = 1
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                                RS9116PowerSaveProcedureTypes.MaxPowerSave)
            power_save = 0
            break
        except:
            time.sleep(5)
            logger.info(f"Retry_count:{count}")
    assert power_save == 0

    device_ip = join_ap(wifi_dut, wifi_access_point, wait_time=60)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    # open/aws , index, port , cert
    load_cert1 = ["open", 0, port1, cert1]
    load_cert2 = ["open", 1, port2, cert2]
    load_cert3 = ["open", 2, port3, cert3]

    result_load_certificate = load_certificates(wifi_dut, ssl_server, load_cert1, load_cert2, load_cert3)
    logger.info(f"Socket_id received{result_load_certificate}")

    data_tx_rx(wifi_dut, ssl_server, result_load_certificate, send_count=2)

    for socket in result_load_certificate:
        logger.info(f"Closing socket{socket}")
        wifi_dut.interfaces.wifi.close_socket(socket)

@pytest.mark.skip()
@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": RS9116Band.Default,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1
    }
)
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
def test_concurrent_mode_C19647(firmware_loader, wifi_dut, wifi_access_point, wifi_client, ssl_server, cert1, logger):

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    bytes_sent = (pkt_count * buffer_length)
    #DUT as STA
    logger.info("join AP")
    ping_count = 10
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger.info(f"wifi_join status: {status}")
    ip_fail = 1
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.start_ip()
            ip_fail = 0
            break
        except:
            time.sleep(5)
            logger.info(f"Retry_count:{count}")
    assert ip_fail == 0, "Getting IP failed"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status == 1

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
    wifi_dut.interfaces.wifi.close_socket(0)
