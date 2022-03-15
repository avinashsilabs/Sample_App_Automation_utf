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
    DeviceConstants,
    RS9116CustomFeatureBitMap,
)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import time
import string
import random
from random import randint


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames 
        5. Initiate BLE advertise/scan

    Author: Jyothi Nagireddy
"""


class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer=None, testcase=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase

    def run(self):
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        logger().info(f"this thread is used for wifi join")
        with TimeMeasurer() as t:
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(" ")[11].strip(")")
            logger().info(f"AP BSSID = {ap_bssid}")
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            time.sleep(10)
            logger().info(f"This API Enables the DHCP in DUT")
            result = self.wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, self.wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            logger().info("DUT to power save in Wifi+bluetooth mode")
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(15)
            logger().info(
                f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            packet_filter1 = (
                f"!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or "
                f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
                f"(wlan.fc.type_subtype == 0x000b))"
            )

            logger().info(f"Validating the power management bit")
            packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
            logger().info(f"Initiate ping from third party wifi-client to DUT")
            status = ping(device_ip, 300)
            assert status == 1
        logger().info(f"Associated and ping, Scan in {t.duration} seconds")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], (
            "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
            "in sniffer"
        )

        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter2
        )["packet_count"], "Unable to find power management bit 1 in sniffer "


class SSLThread(ThreadBase):
    def __init__(
        self,
        wifi_dut,
        wifi_access_point,
        ssl_server=None,
        ssl_client=None,
        remote_socket=None,
        protocol=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ssl_server = ssl_server
        self.ssl_client = ssl_client
        self.remote_socket = remote_socket
        self.protocol = protocol

    def run_ssl_server(self, device_ip):
        logger()
        pkt_count = self.ssl_server.interfaces.ssl.config["no_of_pkts"]
        buffer_length = self.ssl_server.interfaces.ssl.config["buffer_length"]
        port1 = self.ssl_server.interfaces.ssl.config["device_port1"]
        bytes_sent = pkt_count * buffer_length

        logger().info(
            f"Open ssl server socket in remote device(Raspberry pi or static device"
        )
        self.ssl_server.interfaces.ssl.start_server()
        logger().info(f"Open ssl client socket in the DUT")
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(
            protocol=SocketOptions.SSL_ENABLE
        )
        assert sock == 0
        logger().info(f"Enable ssl option for socket opened")
        self.wifi_dut.interfaces.wifi.set_socket_option(
            sock,
            SocketOptions.SOL_SOCKET,
            SocketOptions.SO_SSL_ENABLE,
            SocketOptions.SSL_ENABLE,
        )

        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        self.wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        logger().info(f"ssl socket opened in DUT connects to the server")
        self.wifi_dut.interfaces.wifi.connect_to_server(
            sock, self.ssl_server.interfaces.ssl, server_port=port1
        )

        logger().info(f"The api returns 100 bytes of random data")
        data_sent = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=100)
        )
        data_length = len(data_sent)
        logger().info(f"DUT sends 100 bytes of data over ssl socket")
        self.wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger().info(f"SSL server receives the data over ssl socket")
        data_receive = self.ssl_server.interfaces.ssl.data_recv_content(
            server_socket_no, data_length
        )
        assert (
            data_sent == data_receive.decode()
        ), "data length sent and received is not matching"

        if self.ssl_server.interfaces.ssl.config["type"] == "ssl.server.ssl_linux":
            self.ssl_server.interfaces.ssl.data_receive(
                server_socket_no, pkt_count, buffer_length
            )
        self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

        bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(
            server_socket_no
        )
        assert bytes_sent == bytes_received, (
            f"Number of bytes sent by DUT and received on the remote peer "
            f"not matched on socket {server_socket_no} "
        )
        logger().info(f"Close socket 1")
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"ssl socket close is failed"

    def run_ssl_client(self, device_ip):
        logger().info(f"The below api opens ssl server socket in the DUT")
        sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
        assert sock == 0
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        self.wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        logger().info(
            f"Connect from third party device to the socket opened in the DUT"
        )
        self.ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
        logger().info(f"DUT")
        socket_id = self.wifi_dut.interfaces.wifi.accept(sock)
        logger().info(f"The api returns 100 bytes of random data")
        data_sent = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=100)
        )
        data_length = len(data_sent)
        logger().info(f"DUT sends 100 bytes of data over ssl socket")
        self.wifi_dut.interfaces.wifi.send_data(socket_id, data_length, data_sent)
        logger().info(
            f"SSL client socket opened in third-party device receives the data"
        )
        data_receive = self.ssl_client.interfaces.ssl.data_recv(data_length)
        logger().info(f"DUT closes the tcp socket")
        result = self.wifi_dut.interfaces.wifi.close_socket(socket_id)
        assert b"success" in result, "unable to close opened tcp socket"
        logger().info(f"DUT closes the tcp socket")
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        assert (
            data_sent == data_receive.decode()
        ), "data length sent and received is not matching"

    def run_traffic_tcp_udp(self, device_ip):
        if self.protocol == "TCP":
            self.remote_socket.interfaces.socket.start_server()
            logger().info(f"DUT opens tcp client socket")
            sock = self.wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger().info(f"Socket binds at (device_ip, 5001) in DUT")
            self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
            logger().info(f"tcp socket opened in DUT connects to the tcp server")
            self.wifi_dut.interfaces.wifi.connect_to_server(
                sock, self.remote_socket.interfaces.socket
            )
        elif self.protocol == "UDP":
            logger().info(f"Open UDP socket remotely")
            self.remote_socket.interfaces.socket.start_server(socket_type=1)
            logger().info(f"Open UDP socket in the DUT")
            sock = self.wifi_dut.interfaces.wifi.open_udp_client_socket()
            assert sock == 0, "socket id received is not matched. Expected is 0"
            logger().info(f"DUT binds to socket(device_ip, 5001")
            self.wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
        for count in range(0, 10):
            k = randint(20, 220)
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=k)
            )
            buffer_length = len(tx_buffer)
            if self.protocol == "TCP":
                logger().info(f"send 50 bytes of data from tcp server opened remotely")
                self.remote_socket.interfaces.socket.send_data_tcp(tx_buffer)

            elif self.protocol == "UDP":
                self.remote_socket.interfaces.socket.send_data_udp(
                    tx_buffer, device_ip, port=5001
                )
            logger().info(
                f"DUT receives data over tcp socket after execution of below api"
            )
            buffer_length_rx, buffer_rx = self.wifi_dut.interfaces.wifi.receive_from(
                socket_id=sock, data_len=buffer_length
            )
            assert (
                buffer_length == buffer_length_rx
            ), f"buffer length sent and received is not matched when sending {k} bytes "
            assert (
                tx_buffer.encode() == buffer_rx
            ), "contents of data sent and receive are not matched"
        logger().info(f"DUT closes the tcp socket")
        result = self.wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"
        if self.protocol == "TCP":
            self.remote_socket.interfaces.socket.socket_close_indication(1)

    def run(self):
        logger().info(f"Join Wi-Fi Access Point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        time.sleep(10)
        logger().info(
            f"DUT gets ipaddress through DHCP process after start_ip API is executed"
        )
        self.wifi_dut.interfaces.wifi.start_ip()
        logger().info(
            f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called"
        )
        logger().info(f"to put DUT to power save in Wifi+bluetooth mode")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        logger().info(f"The below api parses DUTs IP address")
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        if self.ssl_server:
            self.run_ssl_server(device_ip)

        elif self.ssl_client:
            self.run_ssl_client(device_ip)

        elif self.remote_socket:
            self.run_traffic_tcp_udp(device_ip)


class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if self.mode == "ble_master":
            logger().info(f"Start DUT")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            logger().info(f"Start ble client")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None
            time.sleep(1)
            logger().info(f"Start scanning and connect to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=30
            )
            timeout = 120
            logger().info(f"connect")
            self.wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=bt_client_address, timeout=timeout
            )
            logger().info(f"Disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=bt_client_address
            )

        if self.mode == "ble_slave":
            logger().info(f" this thread used for sta+ble as a slave")
            logger().info(f"Set up DUT for BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info(f"Begin Scanning for BLE devices")
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address
            )
            assert bt_client_address is not None
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            logger().info(f"See that we found our device")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)

            logger().info(f"Connecting will automatically stop advertising")
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


class ScanThread(ThreadBase):
    def __init__(
        self,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all = select_channel_all

    def run(self):
        logger().info(f"thread for scan functionality")
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
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                with TimeMeasurer() as t:
                    validation = True
                    logger().info("configuring the Sniffer with the channel")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )

                    logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.testcase
                    )
                    logger().info("Setting DUT in wlan power save...")
                    self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode8
                    )
                    logger().info("Setting DUT in bt power save...")
                    self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode8
                    )
                    logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_2_4=channel_bitmap_2_4,
                        scan_feature=scan_feature_extend,
                    )
                    logger().info(ap_mac)
                    assert len(ap_mac) >= 1
                    channel_selected = 0
                    for count in ap_mac:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1
                    logger().info(f"Validating Broadcast Probe request")
                    packet_filter1 = f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )[
                        "packet_count"
                    ], "Unable to find Broadcast Probe request packet in sniffer"
                assert channel_selected == len(ap_mac)
                logger().info(f"Scan in {t.duration} seconds")

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            logger().info(f" {channel_list}")
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_5 += 1 << (count - 1)
                scan_expected_time += 100
            scan_feature_extend = 0
            for channel in channel_list:
                logger().info(f"initiates the access point with channel given in list")
                self.wifi_access_point.interfaces.wifi.start_ap(
                    channel=channel_list[channel]
                )
                with TimeMeasurer() as t:
                    validation = True
                    logger().info("configuring the Sniffer with the channel")
                    self.wifi_sniffer.interfaces.capture.configure_interface(
                        channel=self.wifi_access_point.interfaces.wifi.channel
                    )
                    logger().info(
                        "start capturing with Sniffer by giving the test case name as filename"
                    )
                    self.wifi_sniffer.interfaces.capture.start_capture(
                        capture_file=self.testcase
                    )
                    logger().info("Setting DUT in wlan power save...")
                    self.wifi_dut.interfaces.wifi.power_save(
                        RS9116PowerSaveModes.PowerSaveMode8
                    )
                    logger().info("Setting DUT in bt power save...")
                    self.wifi_dut.interfaces.wifi.bt_power_save(
                        RS9116PowerSaveModes.PowerSaveMode8
                    )
                    logger().info(
                        f"enables the scan in DUT with the given channel bitmap value"
                    )
                    ap_mac = self.wifi_dut.interfaces.wifi.scan_selective_channel(
                        channel=0,
                        ssid=None,
                        scan_bitmap_5=channel_bitmap_5,
                        scan_feature=scan_feature_extend,
                    )
                    logger().info(ap_mac)
                    assert len(ap_mac) >= 1
                    channel_selected = 0
                    for count in ap_mac:
                        for device_channel in channel_list:
                            if count.rf_channel == device_channel:
                                channel_selected = channel_selected + 1

                    logger().info(f"Validating Broadcast Probe request")
                    packet_filter1 = f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                    time.sleep(5)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    logger().info("Validating Broadcast Probe request")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                        validation, packet_filter1
                    )[
                        "packet_count"
                    ], "Unable to find Broadcast Probe request packet in sniffer"
                assert t.duration < 25
                logger().info(f"Scan in {t.duration} seconds")

        if self.select_channel_all:
            validation = True
            logger().info("configuring the Sniffer with the channel")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )

            logger().info(
                "start capturing with Sniffer by giving the test case name as filename"
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.testcase
            )
            with TimeMeasurer() as t:
                logger().info("Setting DUT in wlan power save...")
                self.wifi_dut.interfaces.wifi.power_save(
                    RS9116PowerSaveModes.PowerSaveMode8
                )
                logger().info("Setting DUT in bt power save...")
                self.wifi_dut.interfaces.wifi.bt_power_save(
                    RS9116PowerSaveModes.PowerSaveMode8
                )
                time.sleep(5)
                logger().info(f"enables the scan in dut on channel 0")
                logger().info(f"Scan for the AP's")
                ap_mac = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                packet_filter1 = (
                    f"wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff"
                )
                logger().info(ap_mac)
                assert len(ap_mac) >= 1
                logger().info(f"Validating Broadcast Probe request")
            assert t.duration < 20
            time.sleep(5)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Validating Broadcast Probe request")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )[
                "packet_count"
            ], "Unable to find Broadcast Probe request packet in sniffer"


class RejoinThread(ThreadBase):
    def __init__(
        self,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.deauth_frame = deauth_frame
        self.Aplost = Aplost

    def run(self):
        logger().info(
            f"rejoin thread for the ap when ap lost and deauth frame scenario"
        )
        if self.Aplost:
            validation = True
            logger().info("configuring the Sniffer with the channel")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )

            logger().info(
                "start capturing with Sniffer by giving the test case name as filename"
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.testcase
            )
            time.sleep(10)
            logger().info(f"Scan for the AP's")
            ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
            ap_bssid = str(ap_mac[0]).split(" ")[11].strip(")")
            logger().info(f"AP BSSID = {ap_bssid}")
            self.wifi_dut.interfaces.wifi.rejoin(
                rejoin_max=10,
                scan_interval=6,
                beacon_missedcount=40,
                first_time_retry=0,
            )
            logger().info(f"Join Wi-Fi Access Point")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            time.sleep(10)
            logger().info(f"This API Enables the DHCP in DUT")
            result = self.wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, self.wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            logger().info("DUT to power save in Wifi+bluetooth mode")
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(15)
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            logger().info(
                f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            packet_filter1 = (
                f"!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or "
                f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
                f"(wlan.fc.type_subtype == 0x000b))"
            )

            logger().info(f"Validating the power management bit")
            packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
            status = ping(device_ip, 100)
            assert status == 1
            self.wifi_access_point.interfaces.wifi.stop_ap()
            time.sleep(2)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info(
                "Validating Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )["packet_count"], (
                "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
                "in sniffer"
            )
            logger().info(" Validate power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter2
            )["packet_count"], "Unable to find power management bit 1 in sniffer "
            logger().info(f"Verified device is in power save")

        if self.deauth_frame:
            validation = True
            logger().info("configuring the Sniffer with the channel")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel
            )

            logger().info(
                "start capturing with Sniffer by giving the test case name as filename"
            )
            self.wifi_sniffer.interfaces.capture.start_capture(
                capture_file=self.testcase
            )
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info("DUT to power save in Wifi+bluetooth mode")
            self.wifi_dut.interfaces.wifi.power_save(2)
            self.wifi_dut.interfaces.wifi.bt_power_save(2)
            logger().info(f"Fetches the DUT mac address")
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")
            logger().info(
                f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            packet_filter1 = (
                f"!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or "
                f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
                f"(wlan.fc.type_subtype == 0x000b))"
            )

            logger().info(f"Validating the power management bit")
            packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()

            logger().info(
                "Validating Probe req(Broadcast/Unicast), authentication ,association, eapol"
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter1
            )["packet_count"], (
                "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
                "in sniffer"
            )
            logger().info(" Validate power management bit 1")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                validation, packet_filter2
            )["packet_count"], "Unable to find power management bit 1 in sniffer "

            logger().info(f"Verified device is in power save")


class RejoinThreadbypass(ThreadBase):
    def __init__(
        self,
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.deauth_frame = deauth_frame
        self.Aplost = Aplost

    def run(self):
        logger().info(
            f"rejoin thread for the ap when ap lost and deauth frame scenario"
        )
        validation = True
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(10)
        self.wifi_dut.interfaces.wifi.rejoin(
            rejoin_max=10, scan_interval=6, beacon_missedcount=40, first_time_retry=0
        )
        logger().info(f"Scan for the AP's")
        ap_mac = self.wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(" ")[11].strip(")")
        logger().info(f"AP BSSID = {ap_bssid}")
        logger().info(f"Join Wi-Fi Access Point")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        time.sleep(10)
        logger().info("DUT to power save in Wifi+bluetooth mode")
        self.wifi_dut.interfaces.wifi.power_save(2)
        self.wifi_dut.interfaces.wifi.bt_power_save(2)
        time.sleep(15)
        logger().info(f"Fetches the DUT mac address")
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        logger().info(
            f"Validate Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        packet_filter1 = (
            f"!(wlan.fc.type_subtype == 0x0008) and ((wlan.tag.number == 45 ) or "
            f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or "
            f"(wlan.fc.type_subtype == 0x000b))"
        )

        logger().info(f"Validating the power management bit")
        packet_filter2 = f"wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}"
        self.wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(2)
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            "Validating Probe req(Broadcast/Unicast), authentication ,association, eapol"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter1
        )["packet_count"], (
            "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
            "in sniffer"
        )
        logger().info(" Validate power management bit 1")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            validation, packet_filter2
        )["packet_count"], "Unable to find power management bit 1 in sniffer "
        logger().info(f"Verified device is in power save")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_master_C20183(
    wifi_dut, ble_client, wifi_access_point, wifi_sniffer
):
    mode = "ble_master"
    testcase = "sta + ble connection as a master"
    with WifiThread(
        wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_slave_C20182(
    wifi_dut, ble_client, wifi_access_point, wifi_sniffer
):
    mode = "ble_slave"
    testcase = "sta + ble connection as a slave"
    with WifiThread(
        wifi_dut, wifi_access_point, wifi_sniffer, testcase=testcase
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_selective_channels_2_4_C20208(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = False
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    mode = "ble_slave"
    testcase = "scan in selective channel in 2_4 + ble"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_all_channels_2_4_C20207(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    testcase = "scan in all channels in 2_4 + ble"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd
        | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"]
)
def test_threading_selective_channels_5(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = False
    channel_2_4_list = []
    channel_5_list = {1: 36, 2: 44, 3: 48}
    mode = "ble_slave"
    testcase = "scan in selective channel in 5 + ble"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.Default
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd
        | RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
        "band": 1,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_all_channels_5_C20209(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    testcase = "scan in all channels in 5 + ble"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
def test_threading_sta_ble_rejoin_C20218(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    Aplost = True
    deauth_frame = ""
    mode = "ble_slave"
    testcase = "rejoin and ble connection "
    with RejoinThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"passphrase": "thisisatesthyderabad"})
def test_threading_sta_ble_rejoin_deauth_C20219(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    Aplost = ""
    deauth_frame = True
    mode = "ble_slave"
    testcase = "rejoin_deauth + ble connection"
    with RejoinThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_selective_channels_2_4_bypass_C20249(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = ""
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    mode = "ble_slave"
    testcase = "selective channels in 2_4 channels in bypass"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_all_channels_2_4_bypass_C20248(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    testcase = "all channels in 2_4 channels in bypass"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_selective_channels_5_bypass_C20251(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = ""
    channel_2_4_list = []
    channel_5_list = {1: 36, 2: 44, 3: 48}
    mode = "ble_slave"
    testcase = "selective channels in 5 channels in bypass"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 1,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_all_channels_5_bypass_C20250(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    testcase = "all channels in 5 channels in bypass"
    with ScanThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        channel_2_4_list,
        channel_5_list,
        select_channel_all,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
def test_threading_sta_ble_rejoin_bypass_C20259_C20261(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    Aplost = True
    deauth_frame = ""
    mode = "ble_slave"
    testcase = "rejoin + ble connection as slave in bypass"
    with RejoinThreadbypass(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):

        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_access_point", wifi={"passphrase": "thisisatestjyothi", "standard": "11n"}
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"]
)
def test_threading_sta_ble_rejoin_deauth_bypass_C20260(
    wifi_dut, wifi_access_point, wifi_sniffer, ble_client
):
    Aplost = ""
    deauth_frame = True
    mode = "ble_slave"
    testcase = "rejoin_deauth + ble connection in bypass"
    with RejoinThread(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        Aplost,
        deauth_frame,
        testcase=testcase,
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_ssl_ble_slave_C20232(
    wifi_dut, ble_client, wifi_access_point, ssl_server, logger
):
    mode = "ble_slave"
    with SSLThread(
        wifi_dut, wifi_access_point, ssl_server=ssl_server
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default
        | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_ssl_server_ble_slave_C20232_1(
    wifi_dut, ble_client, wifi_access_point, ssl_client, logger
):
    mode = "ble_slave"
    with SSLThread(
        wifi_dut, wifi_access_point, ssl_client=ssl_client
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_tcp_ble_slave_C20232_C20248(
    wifi_dut, ble_client, wifi_access_point, remote_socket, logger
):
    mode = "ble_slave"
    with SSLThread(
        wifi_dut, wifi_access_point, remote_socket=remote_socket, protocol="TCP"
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["reset", "init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_sta_udp_ble_slave_C20248(
    wifi_dut, ble_client, wifi_access_point, remote_socket, logger
):
    mode = "ble_slave"
    with SSLThread(
        wifi_dut, wifi_access_point, remote_socket=remote_socket, protocol="UDP"
    ), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)
