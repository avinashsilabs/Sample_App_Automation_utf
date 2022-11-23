import re
import time
from utf.utils.logger import get_logger
import pytest
from datetime import datetime, timedelta
from _queue import Empty
from asyncio import QueueEmpty
from utf.utils.thread_base import ThreadBase
from utf.utils.iperf.iperf_utils import ping, get_host_ip
import random
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveProcedureTypes, RS9116ExtCustomFeatureBitMap, SocketOptions, RS9116AsyncEventType, DeviceConstants, RS9116CustomFeatureBitMap
)

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
        1. Configure the DUT in mentioned opermode parameters
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify the file download from the servers 

    Author: Jyothi Nagireddy
"""

device_port = 5001

def fw_download_from_aws_server(wifi_dut, aws_s3):
    status = aws_s3.interfaces.s3.upload_file('/app/manifest/RS9116W.2.7.0.37.rps',
                                              "utf-test", "RS9116W.2.7.0.37.rps")
    assert status is True, f"unable to upload"
    logger().info(f"upload successful")
    url = aws_s3.interfaces.s3.get_file_url("utf-test", "eu-west-2", "RS9116W.2.7.0.37.rps")
    assert url == "https://utf-test.s3.eu-west-2.amazonaws.com/RS9116W.2.7.0.37.rps"
    result = wifi_dut.interfaces.wifi.get_firmware_image(url)
    assert result, "fetched data is empty,failed to get data"


def join_get_ip(wifi_dut, wifi_access_point, utf_constants):
    ping_count = utf_constants.get("ping_count")
    for count in range(1, 3):
        try:
            scan_fail = 1
            logger().info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel,
                                          ssid=None)
            scan_fail = 0
            break
        except:
            logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger().info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"
    for count in range(1, 4):
        try:
            join_fail = 1
            logger().info("***************Joining to the Wifi Access Point*****************")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger().info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"

    for count in range(1, 4):
        try:
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
            device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"Found device ip: {device_ip}")
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed...retry count -> {count}")
            time.sleep(1)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(
        f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put")
    logger().info(f"DUT to power save in Wifi+bluetooth mode")
    enable_wifips = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifips, f" unable to enable the wifips"
    enable_btps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_btps, f"unable to enable the btps"
    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    return device_ip, dut_mac_address


def aws_shadow_connection(aws_iot_dut, utf_constants):
    test_execution_time = utf_constants.get("time_duration")
    end_time = datetime.now() + timedelta(hours=test_execution_time)
    start_time = datetime.now()
    aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_init()
    time.sleep(2)
    shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateAccepted
     ]
    shadow_update_rejected_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateRejected
      ]
    shadow_update_timeout_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateTimeout
     ]
    while datetime.now() < end_time:
         aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(random.randint(1, 100))
         try:
            shadow_update_accepted_event_queue.get(timeout=60)
         except(QueueEmpty, Empty):
            # did not receive update accepted event
            pass
         try:
            shadow_update_rejected_event_queue.get(timeout=60)
            rejected_event_counter = rejected_event_counter + 1
         except(QueueEmpty, Empty):
            # did not receive rejected event
            pass
         try:
            shadow_update_timeout_event_queue.get(timeout=60)
            timeout_event_counter = timeout_event_counter + 1
         except(QueueEmpty, Empty):
            # did not receive timeout event
             pass
    logger().info(f"aws shadow connect success")


def dns_ip(wifi_dut):
    result = wifi_dut.interfaces.wifi.dns_get(4, "https://awsfw.s3.eu-west-2.amazonaws.com", "NULL", "NULL")
    dns_response = result.decode()
    ip_sen = dns_response.split("\n")
    ip_str = ip_sen[1]
    ip_dns = ip_str.split(":")
    server_ip = ip_dns[1]
    logger().info(f"dns_response_ip : {server_ip}")
    time.sleep(10)
    return server_ip


def ssl_socket_connect(wifi_dut, device_ip=None, server_port=None, server_ip=None):
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    logger().info(f'Socket_id = {sock}')
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, server_ip, server_port)


class JoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, utf_constants):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants

    def run(self):
        join_get_ip(self.wifi_dut, self.wifi_access_point, self.utf_constants)

class AwsshadowConnect(ThreadBase):
    def __init__(self, aws_iot_dut, test_execution_time):
        super().__init__()
        self.aws_iot_dut = aws_iot_dut
        self.test_execution_time = test_execution_time

    def run(self):
        aws_shadow_connection(self.aws_iot_dut, self.test_execution_time)



class DNSIPThread(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        dns_ip(self.wifi_dut)


class SslConnectThread(ThreadBase):
    def __init__(self, wifi_dut, device_ip=None, server_port=None, server_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.device_ip = device_ip
        self.server_port = server_port
        self.server_ip = server_ip

    def run(self):
        ssl_socket_connect(self.wifi_dut, self.device_ip, self.server_port, self.server_ip)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"6kb.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_download_data_from_https_server_C42042_1(wifi_sniffer, wifi_dut, utf_constants, wifi_access_point, ssl_server, http_server, index_path, remote_socket):
    iter_count = utf_constants.get("iter_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42042_1')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    ssl_server.interfaces.ssl.start_server()
    server_port = http_server.interfaces.http.port
    server_address = http_server.interfaces.http.hostname_or_ip_address
    for i in range(0, iter_count):
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        logger().info(f'Socket_id = {sock}')
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, server_address, server_port)
        logger().info(f"Download started")
        logger().info("fetching the http data using get method")
        url = "https://" + server_address + "/" + index_path
        result = wifi_dut.interfaces.wifi.get_firmware_image(url)
        assert result, "fetched data is empty,failed to get data"
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_download_data_from_https_server_C42042_2(wifi_sniffer, wifi_dut, utf_constants, wifi_access_point, ssl_server, http_server, index_path, remote_socket):
    iter_count = utf_constants.get("iter_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42042_2')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    ssl_server.interfaces.ssl.start_server()
    server_port = http_server.interfaces.http.port
    server_address = http_server.interfaces.http.hostname_or_ip_address
    for i in range(0, iter_count):
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        logger().info(f'Socket_id = {sock}')
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, server_address, server_port)
        logger().info(f"Download started")
        logger().info("fetching the http data using get method")
        url = "https://" + server_address + "/" + index_path
        result = wifi_dut.interfaces.wifi.get_firmware_image(url)
        assert result, "fetched data is empty,failed to get data"
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid| RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"10MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_download_data_from_https_server_C42042_3(wifi_sniffer, wifi_dut, utf_constants, wifi_access_point, ssl_server, http_server, index_path, remote_socket):
    device_port = 5001
    iter_count = utf_constants.get("iter_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42042_3')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    ssl_server.interfaces.ssl.start_server()
    server_port = http_server.interfaces.http.port
    server_address = http_server.interfaces.http.hostname_or_ip_address
    for i in range(0, iter_count):
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        logger().info(f'Socket_id = {sock}')
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, server_address, server_port)
        logger().info(f"Download started")
        logger().info("fetching the http data using get method")
        url = "https://" + server_address + "/" + index_path
        result = wifi_dut.interfaces.wifi.get_firmware_image(url, timeout=1200)
        assert result, "fetched data is empty,failed to get data"
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SNTPClient,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid| RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.htm"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_download_data_from_https_server_C42042_4(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, ssl_server, http_server, index_path):
    iter_count = utf_constants.get("iter_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42042_4')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    ssl_server.interfaces.ssl.start_server()
    server_port = http_server.interfaces.http.port
    server_address = http_server.interfaces.http.hostname_or_ip_address
    for i in range(0, iter_count):
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        logger().info(f'Socket_id = {sock}')
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, server_address, server_port)
        logger().info(f"Download started")
        logger().info("fetching the http data using get method")
        url = "https://" + server_address + "/" + index_path
        result = wifi_dut.interfaces.wifi.get_firmware_image(url, timeout=12000)
        assert result, "fetched data is empty,failed to get data"
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_allegion_aws_fw_download_C42044(wifi_sniffer, wifi_access_point, wifi_dut, aws_s3, http_server, utf_constants):
    logger().info(f"****************************C42044**********************")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42044')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    server_ip = dns_ip(wifi_dut)
    server_port = http_server.interfaces.http.port
    time.sleep(10)
    ssl_socket_connect(wifi_dut, device_ip=device_ip, server_port=server_port, server_ip=server_ip)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    fw_download_from_aws_server(wifi_dut, aws_s3)
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_connection_fw_download_C42045(wifi_sniffer, wifi_access_point, wifi_dut, aws_s3, http_server, aws_iot_dut, utf_constants):
    logger().info(f"*******************C42045***********************")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42045')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    server_ip = dns_ip(wifi_dut)
    server_port = http_server.interfaces.http.port
    ssl_socket_connect(wifi_dut, device_ip=device_ip, server_port=server_port, server_ip=server_ip)
    aws_shadow_connection(aws_iot_dut, utf_constants)
    fw_download_from_aws_server(wifi_dut, aws_s3)
    logger().info("AWS server disconnection from DUT")
    aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SNTPClient,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_connection_unsecure_connection_fw_download_C42046(wifi_sniffer, wifi_access_point, wifi_dut, aws_s3, http_server, aws_iot_dut, utf_constants):
    logger().info(f"***************C42046********************")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C42046')
    time.sleep(3)
    device_ip, dut_mac_address = join_get_ip(wifi_dut, wifi_access_point, utf_constants)
    server_ip = dns_ip(wifi_dut)
    server_port = http_server.interfaces.http.port
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, server_ip, server_port)
    aws_shadow_connection(aws_iot_dut,  utf_constants)
    fw_download_from_aws_server(wifi_dut, aws_s3)
    logger().info("AWS server disconnection from DUT")
    aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
    wifi_dut.interfaces.wifi.leave()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


