import time
import pytest
import threading
import string
import random
from random import randint
from threading import Thread
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils import get_tls_certificate_dir
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116PowerSaveProcedureTypes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, SocketOptions, \
    RS9116ExtTCPIPFeatureBitMap ,RS9116ConfigFeatureBitMap, SocketParams, DeviceConstants, SocketType, RS9116CertificateType

ping_count = 30

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Author: Vishakha
"""

def join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut,capture_filename):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"DUT firmware version: {result}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger().info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger().info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger().info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger().info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"
    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"

def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True,
                     expected="RSI_BLE_ENCRYPT_STARTED_EVENT",skip_scan=False):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if start_needed:
            logger().info(f"Set up DUT for BLE master role")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Started BLE in DUT")
            assert ble_dut_address, f"Unable to start ble"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to start smp advertising "
        time.sleep(5)
        if not skip_scan:
            logger().info("Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(5)
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        logger().info("BLE Connection success")

    if mode == "ble_slave":
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to start ble"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to start smp scanning "
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[wifi_dut.interfaces.wifi.ble_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
        )
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info("BLE Connection success")
        time.sleep(2)
    return ble_client_address, ble_dut_address

class tx_rx:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def receive_data_socket(self, remote_socket, logger, no_of_pkts, data_size, proto_type=0):
        fail_count = 0
        if proto_type == 0:
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
        else:
            remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
        for count in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.interfaces.socket.recv_data_tcp(data_size)
            else:
                data, address = remote_socket.interfaces.socket.recv_data_udp(data_size)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")

    def send_data(self, remote_socket, logger, data_size, test_run_time=300, proto_type=0, server_ip=None,
                  server_port=None):
        sw = Stopwatch()
        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=data_size))
        while sw.elapsed_sec < test_run_time:
            if proto_type == 0:
                data = remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
            else:
                data = remote_socket.interfaces.socket.send_data_udp(tx_buffer, server_ip, server_port)
                time.sleep(0.1)
            self.sent_data = self.sent_data + data
        logger().info(f"Total bytes sent on socket opened remotely -> {self.sent_data}")


#WLAN TCP-Tx packet loss with LE advertising
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_packet_loss_C20222(wifi_sniffer,wifi_dut,wifi_access_point,ble_client,remote_socket, remote_socket_factory):
    remote_socket.interfaces.socket.time_limit = 1800
    capture_filename = "test_TCP_packet_loss_C20222"
    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to start ble"
    wifi_dut.interfaces.wifi.ble_start_advertising()
    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    # Join Wi-Fi Access Point
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename)

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    sock_port = 5001
    buffer_length = 500
    socket_id = 0
    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 2"
    logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

    bytes_sent = remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
    logger().info(f"bytes sent is {bytes_sent}")

    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_id,
                                                                        data_len=buffer_length)
    logger().info(f" buffer_length_rx{buffer_length_rx}")
    logger().info(f"buffer_rx {buffer_rx}")
    logger().info(f"buffer_length {buffer_length}")
    assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} " \
                                              f"opened in the DUT is not matched "
    packet_loss = (((buffer_length - buffer_length_rx) / buffer_length) * 100)
    logger().info(f"packet loss tx {packet_loss}")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, f"Unable to start smp scanning "
    time.sleep(5)

    logger().info(f"See that we found our device")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )
    logger().info(f"Start scanning to ble client")
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger().info("Successfully closed opened socket in the DUT")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


#Wlan Multicast data UDP_TX and UDP_RX when DUT connected as slave
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Multicast_C20227(wifi_sniffer,wifi_dut,wifi_access_point,ble_client,multicast_client,remote_socket):
    capture_filename = "test_Multicast_C20227"
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()
    logger().info(f"DUT joining to the multicast group {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
    socket_id = wifi_dut.interfaces.wifi.socket_udp_async(SocketParams.AF_INET, SocketParams.SOCK_DGRAM, 0)
    assert socket_id == 0, f"socket id received is wrong, expected is 0"
    logger().info(f"socket id received is {socket_id} which is expected")
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(socket_id, device_ip, device_port)

    logger().info(f"Starting server remotely at {multicast_ip} and port number {server_port}")
    multicast_client.interfaces.multicast.start_server()
    logger().info(
        f"Send {no_of_pkts} of packets with buffer length {buffer_length} from remote device to socket address->{multicast_ip}:{device_port}")
    multicast_client.interfaces.multicast.send_multicast_data(multicast_ip, device_port)
    logger().info(f"Successfully sent multicast_ip : {multicast_ip} and device_port : {device_port}")
    multicast_client.interfaces.multicast.socket_close()
    time.sleep(30)
    result = wifi_dut.interfaces.wifi.close_socket(socket_id)
    assert b"success" in result, "unable to close opened socket in the dut"
    logger().info("Successfully closed opened socket in the DUT")
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(socket_id)
    bytes_received = int(result.split(b":")[1])
    bytes_sent = (no_of_pkts * buffer_length)
    packet_loss = (((bytes_sent - bytes_received) / bytes_sent) * 100)
    logger().info(f"Packet loss {packet_loss}")
    assert packet_loss < 20, "Packet loss is not in tolerance level"
    wifi_dut.interfaces.wifi.leave_multicast_group(multicast_ip=multicast_ip)
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


#WLAN Broadcast TX when DUT connected as slave
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.parametrize("number_of_pkts", [500])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Broadcast_C20228(wifi_sniffer,wifi_dut,wifi_access_point,ble_client,remote_socket, number_of_pkts):
    data_size = 1460
    capture_filename = "test_Broadcast_C20228"
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger().info("Starting udp socket remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0, "socket id received is not matched. Expected is 0"
    logger().info(f"socket id received is {sock} which is expected")
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    th_start = Thread(target=tx_rx_obj.receive_data_socket,
                      args=(remote_socket, logger, number_of_pkts, data_size, 1), )
    th_start.start()
    server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
    logger().info(f"Get server IP : {server_ip} ")
    ap_broadcast_ip = '.'.join(server_ip.split('.')[:-1] + ["255"])
    logger().info(f"Broadcast address: '{ap_broadcast_ip}' ")
    server_port = remote_socket.interfaces.socket.server_port
    logger().info(f"Get server port : {server_port} ")
    bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                         server_ip=ap_broadcast_ip, server_port=server_port)
    logger().info(f"Number of bytes sent by dut {bytes_sent}")
    th_start.join(5)
    # DUT closes the socket.socket id is mentioned in sock variable
    logger().info("contents of data sent and receive are matched")
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "Unable to close the udp socket opened in the dut"
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


#WiFi SSL Tx functionality and stability after BLE connection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_ssl_tx_and_stability_C20231(wifi_sniffer,wifi_dut,wifi_access_point,ble_client,ssl_server, cert1, protocol):
    capture_filename = "test_TCP_packet_loss_C20222"
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)
    # Join Wi-Fi Access Point
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1])

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    cert_index = SocketOptions.CERT_INDEX0
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               cert_index)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    logger().info(f"Date Sent :{data_sent} and length of the data {data_length}")

    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = sock + 1
    logger().info(f"data sent server_socket_no {server_socket_no}")
    # # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    logger().info(f"Data received on remote socket opened is {data_receive}")
    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
    logger().info("Data sent by DUT and received on server is matching")

    # Close socket
    wifi_dut.interfaces.wifi.close_socket(sock)
    ssl_server.interfaces.ssl.stop_server()
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
