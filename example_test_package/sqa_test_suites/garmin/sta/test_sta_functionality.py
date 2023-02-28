import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap,RS9116PowerSaveModes, \
    RS9116JoinFeatureBitMap, RS9116Band, RS9116TCPIPFeatureBitMap,RS9116PowerSaveProcedureTypes,RS9116CustomFeatureBitMap,\
    RS9116ExtCustomFeatureBitMap,RS9116ExtTCPIPFeatureBitMap, SocketOptions, SocketType
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from random import randint
from utf.utils.thread_base import ThreadBase
import random
import string
from utf.utils.iperf.iperf_utils import ping, print_dict

def logger():
    return get_logger(__name__)
"""
This function runs below test steps for DUT-RS9116 for WLAN Alone Garmin test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Verification of WiFi BG Scan and connect 
        5. Check for the Standby mode 

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4(6 raspberry device required to run the complete test cases)
        4. Access Point(Third Party AP's)
"""

"""Author: Sairam"""


class Wlan_data_transfer_tx(ThreadBase):
    def __init__(self, host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout, net_perf_client=None,
                 protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.host_ip = host_ip
        self.device_ip = device_ip
        self.rs_helper = rs_helper
        self.timeout = timeout

    def run(self):
        self.rs_helper.run_traffic(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip,
                                   self.timeout, traffic_type="TX")


class Wlan_data_transfer_rx(ThreadBase):
    def __init__(self, host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout, net_perf_client=None,
                 protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.host_ip = host_ip
        self.device_ip = device_ip
        self.rs_helper = rs_helper
        self.timeout = timeout

    def run(self):
        self.rs_helper.run_traffic(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip,
                                   self.timeout, traffic_type="RX")


class Wlan_Firmware_Quering(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        sw = Stopwatch()
        logger().info(f"Firmware quering for 30 seconds")
        while sw.elapsed_sec < 30:
            time.sleep(5)
            result = self.wifi_dut.interfaces.wifi.version()
            logger().info(f"Current Version: {result}")
            time.sleep(5)


class DnsQuering(ThreadBase):
    def __init__(self, wifi_dut, utf_constants):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.utf_constants = utf_constants

    def run(self):
        ping_count = self.utf_constants.get("ping_count")
        logger().info("=======DNS Quering========")
        result = self.wifi_dut.interfaces.wifi.dns_get(4, "www.google.com", "NULL", "NULL")
        dns_response = result.decode()
        ip_sen = dns_response.split("\n")
        ip_str = ip_sen[1]
        dns_ip = ip_str.split(":")
        logger().info(f"dns_response_ip : {dns_ip[1]}")
        logger().info(f"ping_count:{ping_count}")
        status = ping(dns_ip[1], ping_count)
        time.sleep(10)
        assert status == 1, "ping failed ......"

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client| RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_state_withoutpowersave_c20529(wifi_access_point, wifi_dut):
        bcast_in_tim_next_cmd = 1
        beacon_drop = 5000
        bcast_in_tim = 1

        logger().info("scan and connecting to access point.....")
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        logger().info("sending filter broadcast command")
        wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)
        logger().info(f"DUT is going to standy_state by for 30seconds")
        time.sleep(30)
        logger().info(f"Verified standy by for 30seconds")
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
        "wifi_dut",
            wifi=
            {
                "oper_mode": 0,
                "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
                "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
                "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
                "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                    4),
                "set_send_feature_frame": True,
            }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_bgscan_state_withoutpowersave_c20530(wifi_access_point, wifi_dut, rs_helper, utf_constants):
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")
    logger().info(f"DUT will be in connected state for 10 sec")
    time.sleep(10)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                4),
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_bg_scan_withpowersave_c113936(wifi_access_point, wifi_dut,rs_helper, utf_constants ):
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=True)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC : {ap_mac}")
    logger().info(f"DUT will be in connected state for 10 sec")
    time.sleep(10)
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client| RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_state_withpowersave_c113935(wifi_access_point, wifi_dut):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 5000
    bcast_in_tim = 1

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f'DUT ip {device_ip}')

    logger().info("sending filter broadcast command")
    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info(f"DUT will be in connected standby_state for 30 sec")
    time.sleep(30)
    logger().info(f"Verifying standy by for 30seconds")
    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DNSClient,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_ssl_tx_c20527(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, utf_constants):
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        ping_count = utf_constants.get("ping_count")
        pkt_count = 30000
        buffer_length = 1370
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        '''Verify Wi-Fi SSL Tx'''
        capture_file = "test_ssl_tx_c20527"
        file_name = "test_ssl_tx_c20527"
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f"=========== configured the sniffer on {channel} on NUC.")
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ssl_tx_c20527')
        time.sleep(3)
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f" DUT_Version: {result}")
        result = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f" DUT_mac_address is: {result}")
        logger().info("============ Associating the dut to AP ================")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info("sending static ipconfiguration address")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'Device is {device_ip}')
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(2)
        ssl_server.interfaces.ssl.start_server()
        logger().info(f"###Open ssl client socket in the DUT###")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger().info(f"# Enable ssl option for socket opened")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        logger().info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"****ssl socket opened in DUT connects to the server****")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        logger().info(f"****API returns 100 bytes of random data*****")
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger().info(f"Sending data {data_sent} over socket_no->{sock}")
        logger().info(f" ******DUT sends 100 bytes of data over ssl socket*********")
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger().info(f"***####SSL server receives the data over ssl socket****####")
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger().info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger().info("Data sent by DUT and received on server is matching")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        logger().info(f"Number of bytes sent by dut {result}")
        bytes_sent = result

        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)

        logger().info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(2)
        logger().info(f" ====== STOPPING THE capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()


######Author: Benazeer K #########
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DNSClient,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_connect_discon_c20531(wifi_sniffer, rs_helper, wifi_dut, wifi_access_point, ssl_server, utf_constants, request):
    try:
        logger().info("Verify Wi-Fi and SSL socket connect, disconnect and reconnect functionality")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        wifi_dut.interfaces.wifi.associated = False
        test_name = request.node.name
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(f" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(3)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True)
        iterations = 5
        for count in range(1, iterations):
            ssl_server.interfaces.ssl.start_server()
            logger().info(f"###Open ssl client socket in the DUT###")
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            logger().info(f"# Enable ssl option for socket opened")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            local_port = randint(5001, 60000)
            logger().info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            time.sleep(2)

            logger().info(f"****ssl socket opened in DUT connects to the server****")
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            time.sleep(2)
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            logger().info("Successfully closed opened socket in the DUT")
            time.sleep(2)

    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_tcp_tx_data_tran_with_dns_ping_c20540(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                               wifi_client, rs_helper, utf_constants, request):
    try:
        logger().info("Verify TCP Tx along with DNS ping functionality using WIFI_TCP_TX_DNS")
        test_name = request.node.name
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_tx_wait_time(tx_wait_time=120000)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                        socket_flag=SocketType.ASYNCHRONOUS)
        timeout = 60
        protocol = IperfConstants.TCP
        wlan_traffic_tx = Wlan_data_transfer_tx(host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout,
                                                net_perf_client, protocol)
        dns_ping = DnsQuering(wifi_dut, utf_constants)
        wlan_traffic_tx.start()
        dns_ping.start()

        wlan_traffic_tx.wait_for_exit()
        dns_ping.wait_for_exit()
        # Disconnect the AP
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_tcp_rx_data_tran_c20528(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                 wifi_client, rs_helper, utf_constants, request):
    try:
        test_name = request.node.name
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_tx_wait_time(tx_wait_time=120000)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=True)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                        socket_flag=SocketType.ASYNCHRONOUS)
        wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                               tcp_tx_only_sockets=0,
                                               tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                               tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=10,
                                               tcp_rx_window_div_factor=10)
        timeout = 60
        protocol = IperfConstants.TCP
        wlan_traffic_rx = Wlan_data_transfer_rx(host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout,
                                                net_perf_client, protocol)
        wlan_traffic_rx.start()
        wlan_traffic_rx.wait_for_exit()
        # Disconnect the AP
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            4),
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "band": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
def test_tcp_tx_data_tran_with_firm_version_c20541(net_perf_client, wifi_sniffer, wifi_access_point, wifi_dut,
                                                   wifi_client, rs_helper, utf_constants, request):
    try:
        logger().info("Verify TCP Tx along with Firmware querying")
        test_name = request.node.name
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_tx_wait_time(tx_wait_time=120000)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        time.sleep(2)
        wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                        socket_flag=SocketType.ASYNCHRONOUS)
        timeout = 60
        protocol = IperfConstants.TCP
        wlan_traffic_tx = Wlan_data_transfer_tx(host_ip, wifi_dut, device_ip, wifi_client, rs_helper, timeout,
                                                net_perf_client, protocol)
        firm_ver = Wlan_Firmware_Quering(wifi_dut)
        wlan_traffic_tx.start()
        firm_ver.start()

        wlan_traffic_tx.wait_for_exit()
        firm_ver.wait_for_exit()
        # Disconnect the AP
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "band": 0,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    },
)
def test_ssl_data_transfer_rx_c20525(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, rs_helper, utf_constants, request):
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                       power_save=False)
        pkt_count = 30000
        buffer_length = 1370
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)

        iterations = 2
        for count in range(1, iterations):
            logger().info(f"###############Iteration{count}###############################")
            ssl_server.interfaces.ssl.start_server()
            wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                                   tcp_tx_only_sockets=0,
                                                   tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                                   tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=44,
                                                   tcp_rx_window_div_factor=10)
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                                   socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            logger().info(f" *****# Enable ssl option for socket opened *****#")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, 38,
                                                       128)

            local_port = randint(5001, 60000)
            logger().info(f"#*****Socket binds with device_ip and Port number 5001 in DUT****#")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            logger().info(f"#****ssl socket opened in DUT connects to the server****#")
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            server_socket_no = 1
            pkt_count = 50000
            duration = 60
            with TimeMeasurer() as t:
                ssl_server.interfaces.ssl.send_data_socket(server_socket_no, pkt_count, msg_length=buffer_length,
                                                           duration=duration)
            time_duration = t.duration
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            logger().info("Successfully closed opened socket in the DUT")
            bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
            result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
            bytes_received = int(result.split(b":")[1])
            logger().info(f"bytes sent by remote peer -> {bytes_sent}")
            logger().info(f"bytes received on socket {sock} -> {bytes_received}")
            logger().info(f"SSL rx throughput ->  {(bytes_received * 8) / (1000 * 1000 * time_duration)} Mbps")
            ssl_server.interfaces.ssl.stop_server()
        logger().info("DUT is going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as Ex:
        logger().info("The Occured Exception is ", Ex)
        logger().info(f"Exception: {str(Ex)}")
        raise Ex
    finally:
        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()
