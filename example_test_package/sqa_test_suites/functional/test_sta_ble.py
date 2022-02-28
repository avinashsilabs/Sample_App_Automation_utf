import pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants
    )
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time
import string
import random
from random import randint


def logger():
    return get_logger(__name__)


# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, ssl_server=None, ssl_client=None, remote_socket=None,
                 protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ssl_server = ssl_server
        self.ssl_client = ssl_client
        self.remote_socket = remote_socket
        self.protocol = protocol

    def run_ssl_server(self, device_ip):
        pkt_count = self.ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = self.ssl_server.interfaces.ssl.config['buffer_length']
        port1 = self.ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)

        # Open ssl server socket in remote device(Raspberry pi or static device)
        self.ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0
        # Enable ssl option for socket opened
        self.wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                        SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.ssl_server.interfaces.ssl, server_port=port1)

        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        self.wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        # SSL server receives the data over ssl socket
        data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        assert data_sent == data_receive.decode(), "data length sent and received is not matching"

        if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

        bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                             f"not matched on socket {server_socket_no} "
        # Close socket 1
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"ssl socket close is failed"

    def run_ssl_client(self, device_ip):
        # The below api opens ssl server socket in the DUT
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0
        # Socket binds at (device_ip, 5001) in DUT
        self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        self.wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        # Connect from third party device to the socket opened in the DUT
        self.ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        # DUT
        socket_id = self.wifi_dut.interfaces.wifi.accept(sock)
        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        self.wifi_dut.interfaces.wifi.send_data(socket_id, data_length, data_sent)
        # SSL client socket opened in third-party device receives the data
        data_receive = self.ssl_client.interfaces.ssl.data_recv(data_length)
        # DUT closes the tcp socket
        result = self.wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened tcp socket"
        # DUT closes the tcp socket
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        assert data_sent == data_receive.decode(), "data length sent and received is not matching"

    def run_traffic_tcp_udp(self, device_ip):
        if self.protocol == "TCP":
            self.remote_socket.interfaces.socket.start_server()
            # DUT opens tcp client socket
            sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 0, f"socket id received is wrong, expected is 0"
            # Socket binds at (device_ip, 5001) in DUT
            self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
            # tcp socket opened in DUT connects to the tcp server
            self.wifi_dut.interfaces.wifi.connect_to_server(sock, self.remote_socket.interfaces.socket)
        elif self.protocol == "UDP":
            # Open UDP socket remotely
            self.remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = self.wifi_dut.interfaces.wifi.open_udp_client_socket()
            assert sock == 0, "socket id received is not matched. Expected is 0"
            # DUT binds to socket(device_ip, 5001)
            self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        for count in range(0, 10):
            k = randint(20, 220)
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=k))
            buffer_length = len(tx_buffer)
            if self.protocol == "TCP":
                # send 50 bytes of data from tcp server opened remotely
                self.remote_socket.interfaces.socket.send_data_tcp(tx_buffer)

            elif self.protocol == "UDP":
                self.remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=5001)
            # DUT receives data over tcp socket after execution of below api
            buffer_length_rx, buffer_rx = self.wifi_dut.interfaces.wifi.receive_from(socket_id=sock,
                                                                                     data_len=buffer_length)
            assert buffer_length == buffer_length_rx, f"buffer length sent and received is not matched when sending {k} bytes "
            assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
        # DUT closes the tcp socket
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"
        if self.protocol == "TCP":
            self.remote_socket.interfaces.socket.socket_close_indication(1)

    def run(self):
        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        time.sleep(10)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        self.wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called
        # to put DUT to power save in Wifi+bluetooth mode
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        if self.ssl_server:
            self.run_ssl_server(device_ip)

        elif self.ssl_client:
            self.run_ssl_client(device_ip)

        elif self.remote_socket:
            self.run_traffic_tcp_udp(device_ip)


# this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if (self.mode == "ble_master"):
            # Start DUT
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(1)
            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=20)
            # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
            timeout = 120
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if (self.mode == "ble_slave"):
            # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

            # Not legal to start advertising if we're already advertising...
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)

            # Connecting will automatically stop advertising
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

            # Now, we can restart advertising...
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            # ...and stop again
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()


# thread for scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list, select_channel_all):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all = select_channel_all

    def run(self):
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0

        if len(self.channel_2_4_list):
            channel_list = self.channel_2_4_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100

            channel_bitmap_5 = 0
            scan_feature_extend = 0
            for channel in channel_list:
                # initiates the access point with channel given in list
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                with TimeMeasurer() as t:
                    # enables the scan in DUT with the given channel bitmap value
                    scan_results = self.wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                                                        scan_bitmap_5=channel_bitmap_5,
                                                                                        scan_feature=scan_feature_extend)
                    logger().info(scan_results)
                    assert len(scan_results) >= 1

                    channel_selected = 0
                    for count in scan_results:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                assert (t.duration < 3)
                logger().info(f"Scan in {t.duration} seconds")

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_5 += 1 << (count - 1)
                scan_expected_time += 100
            channel_bitmap_2_4 = 0
            scan_feature_extend = 0
            for channel in channel_list:
                # initiates the access point with channel given in list
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                with TimeMeasurer() as t:
                    # enables the scan in DUT with the given channel bitmap value
                    scan_results = self.wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                                                        scan_bitmap_5=channel_bitmap_5,
                                                                                        scan_feature=scan_feature_extend)
                    logger().info(scan_results)
                    assert len(scan_results) >= 1

                    channel_selected = 0
                    for count in scan_results:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                assert (t.duration < 3)
                logger().info(f"Scan in {t.duration} seconds")

        if self.select_channel_all:
            with TimeMeasurer() as t:
                # enables the scan in dut on channel 0
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            assert (t.duration < 1.5)
            logger().info(scan_results)
            time.sleep(5)


# rejoin thread for the ap when ap lost and deauth frame scenario
class RejoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, Aplost, deauth_frame):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.deauth_frame = deauth_frame
        self.Aplost = Aplost

    def run(self):
        if self.Aplost:
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_access_point.interfaces.wifi.stop_ap()
            self.wifi_dut.interfaces.wifi.rejoin()
            time.sleep(2)

        if self.deauth_frame:
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.leave()


# tcp thoughput thread for rx adn tx packets
class TCPPacketThread(ThreadBase):
    def __init__(self, wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client):
        super().__init__()
        self.wifi_networked_dut = wifi_networked_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client

    def run(self):
        time.sleep(5)
        # preparing wifi_dut
        self.wifi_networked_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        ip_config = self.wifi_networked_dut.interfaces.wifi.start_ip()
        device_ip = self.wifi_networked_dut.interfaces.wifi.get_device_ip(ip_config)

        # preparing wifi_client
        if self.wifi_access_point != self.wifi_client:
            self.wifi_client.interfaces.wifi.join_ap(self.wifi_access_point)
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip)
        self.net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        self.wifi_networked_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info("this is IPerf")


# # #thread for tkip with pmk & psk ,AES with pmk & psk
class ModesThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                 WPA_TKIP_reboot):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.WPA_TKIP_PMK = WPA_TKIP_PMK
        self.WPA_AES_PMK = WPA_AES_PMK
        self.WPA_TKIP_PSK = WPA_TKIP_PSK
        self.WPA_AES_PSK = WPA_AES_PSK
        self.WPA_TKIP_reboot = WPA_TKIP_reboot

    def run(self):
        if self.WPA_TKIP_PMK | self.WPA_AES_PMK:
            with TimeMeasurer() as t:
                # This API connects STA to the third party AP with the pmk generated
                self.wifi_dut.interfaces.wifi.join_pmk(self.wifi_access_point.interfaces.wifi.ssid,
                                                       self.wifi_access_point.interfaces.wifi.passphrase)
                time.sleep(10)
            assert (t.duration < 15)
            logger().info(f"Associated in {t.duration} seconds")
        elif self.WPA_TKIP_PSK | self.WPA_AES_PSK:
            with TimeMeasurer() as t:
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                time.sleep(10)
            assert (t.duration < 15)
            logger().info(f"Associated in {t.duration} seconds")
        elif self.WPA_TKIP_reboot:
            with TimeMeasurer() as t:
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                self.wifi_access_point.interfaces.wifi.stop_ap()
                self.wifi_access_point.interfaces.wifi.start_ap()
            assert (t.duration < 15)
            logger().info(f"Associated in {t.duration} seconds")
        # This API Enables the DHCP in DUT
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 3)
        assert status == 1
        time.sleep(1)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
#
# testcase1 #testcase2 for sta+ble master functionality
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_master(wifi_dut, ble_client, wifi_access_point):
    mode = "ble_master"
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
# testcase3 for Sta+ble slave functionality
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_slave(wifi_dut, ble_client, wifi_access_point):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase4 for for selective channels in 2.4 ghz + ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_selective_channels_2_4(wifi_dut, ble_client, wifi_access_point):
    select_channel_all = False
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase5 for all channels in 2.4 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_all_channels_2_4(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1
        }
    )
# testcase6 for selective channels in 5 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_selective_channels_5(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = False
    channel_2_4_list = []
    channel_5_list = {1: 36, 2: 44, 3: 48}
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1
        }
    )
# testcase7 for all channels in 5 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_all_channels_5(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase8 for rejoin functionality when ap lost +ble #testcase 9 for ap user disconnection +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_threading_sta_ble_rejoin(wifi_dut, wifi_access_point, ble_client):
    Aplost = True
    deauth_frame = False
    mode = "ble_slave"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client,
                                                                                               mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase10 for rejoin functionality when deauth frame
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'thisisatesthyderabad', 'standard': "11g"})
def test_threading_sta_ble_rejoin_deauth(wifi_dut, wifi_access_point, ble_client):
    Aplost = False
    deauth_frame = True
    mode = "ble_slave"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client,
                                                                                               mode):
        time.sleep(15)


@pytest.mark.config("net_perf_client",
 net_perf={
        "host_role": IperfConstants.SERVER_MODE, 
        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP,
        }
    )
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

        }
    )
# testcase11 for server mode(tx) packet throughput +ble
def test_throughput_wifi_bt_2(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, net_perf_client, ble_client):
    mode = "ble_slave"
    with TCPPacketThread(wifi_access_point, wifi_networked_dut, wifi_client, net_perf_client), BleThread_connection(wifi_dut,
                                                                                                               ble_client,
                                                                                                               mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase12 for for selective channels in 2.4 ghz + ble in bypass
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_selective_channels_2_4_bypass(wifi_dut, ble_client, wifi_access_point):
    select_channel_all = False
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase13 for all channels in 2.4 ghz +ble in bypass
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_all_channels_2_4_bypass(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1
        }
    )
# testcase14 for selective channels in 5 ghz +ble in in bypass
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_selective_channels_5_bypass(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = False
    channel_2_4_list = []
    channel_5_list = {1: 36, 2: 44, 3: 48}
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1
        }
    )
# testcase15 for all channels in 5 ghz +ble in in bypass
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_all_channels_5_bypass(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,
                    select_channel_all), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase 16 for rejoin functionality when ap lost +ble #testcase 17 for ap user disconnection +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_rejoin_bypass(wifi_dut, wifi_access_point, ble_client):
    Aplost = True
    deauth_frame = False
    mode = "ble_slave"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client,
                                                                                               mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0
        }
    )
# testcase18 for rejoin functionality when deauth frame in bypass
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'thisisatestjyothi', 'standard': "11n"})
def test_threading_sta_ble_rejoin_deauth_bypass(wifi_dut, wifi_access_point, ble_client):
    Aplost = False
    deauth_frame = True
    mode = "ble_slave"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client,
                                                                                               mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
# testcase19 for tkip with pmk +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'TKIP', 'standard': "11g"})
def test_threading_sta_ble_modes_tkip_pmk(wifi_dut, wifi_access_point, ble_client):
    WPA_TKIP_PMK = True
    WPA_AES_PMK = False
    WPA_TKIP_PSK = False
    WPA_AES_PSK = False
    WPA_TKIP_reboot = False
    mode = "ble_slave"
    with ModesThread(wifi_dut, wifi_access_point, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                     WPA_TKIP_reboot), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
# testcase20 for AES with pmk +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": "WPA2", "cipher": 'AES',
                          'standard': "11g"})
def test_threading_sta_ble_modes_AES_pmk(wifi_dut, ble_client, wifi_access_point):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = True
    WPA_TKIP_PSK = False
    WPA_AES_PSK = False
    WPA_TKIP_reboot = False
    mode = "ble_slave"
    with ModesThread(wifi_dut, wifi_access_point, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                     WPA_TKIP_reboot), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
# testcase21 for tkip with psk +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA", "cipher": 'TKIP',
                          'standard': "11g"})
def test_threading_sta_ble_modes_tkip_psk(wifi_dut, wifi_access_point, ble_client):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = False
    WPA_TKIP_PSK = True
    WPA_AES_PSK = False
    WPA_TKIP_reboot = False
    mode = "ble_slave"
    with ModesThread(wifi_dut, wifi_access_point, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                     WPA_TKIP_reboot), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
# testcase22 for AES with psk +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testingpmk", "passphrase": 'Testing_psk', "security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_modes_AES_psk(wifi_dut, wifi_access_point, ble_client):
    WPA_TKIP_PMK = False
    WPA_AES_PMK = False
    WPA_TKIP_PSK = False
    WPA_AES_PSK = True
    WPA_TKIP_reboot = False
    mode = "ble_slave"
    with ModesThread(wifi_dut, wifi_access_point, WPA_TKIP_PMK, WPA_AES_PMK, WPA_TKIP_PSK, WPA_AES_PSK,
                     WPA_TKIP_reboot), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_ssl_ble_slave_TT6227(wifi_dut, ble_client, wifi_access_point, ssl_server, logger):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point, ssl_server=ssl_server), BleThread_connection(wifi_dut, ble_client,
                                                                                              mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_ssl_server_ble_slave_TT6228(wifi_dut, ble_client, wifi_access_point, ssl_client, logger):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point, ssl_client=ssl_client), BleThread_connection(wifi_dut, ble_client,
                                                                                              mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_tcp_ble_slave_T6220(wifi_dut, ble_client, wifi_access_point, remote_socket, logger):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point, remote_socket=remote_socket, protocol="TCP"), BleThread_connection(
            wifi_dut,
            ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_udp_ble_slave_T6220(wifi_dut, ble_client, wifi_access_point, remote_socket, logger):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point, remote_socket=remote_socket, protocol="UDP"), BleThread_connection(
            wifi_dut,
            ble_client, mode):
        time.sleep(15)
