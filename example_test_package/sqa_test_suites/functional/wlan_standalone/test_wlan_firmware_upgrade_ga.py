from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime, timedelta
from utf.utils.logger import get_logger
import time
import pytest
from threading import Thread
import random
from random import randint
import string
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
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants,
    RS9116AsyncEventType,
    RS9116OperatingMode,
    RS9116Band
    )
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf.utils.firmware_manager import FirmwareManager

ping_count = 10

def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


#this thread is used for AP power ON/OFF
class ApWirelessOff(ThreadBase):
    def __init__(self, wifi_access_point,wifi_dut, wait_time,rejoin_failure):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wait_time = wait_time
        self.rejoin_failure = rejoin_failure

    def run(self):
        time.sleep(self.wait_time)
        logger().info(f"Disabling Wireless in AP")
        self.wifi_access_point.interfaces.wifi.stop_ap()
        if self.rejoin_failure:
            time.sleep(120)
            end_time = datetime.now() + timedelta(minutes=2)
            logger().info(f"time start {datetime.now()}")
            while 1:
                """validate rejoin retry failure"""
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [event for event in events if
                                       event.event_type == RS9116AsyncEventType.RejoinError]
                if len(rejoin_error_events):
                    logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
                    break
                else:
                    logger().info(f'RE-JOIN ERROR not observed')
                    assert False
            logger().info(f"time end {datetime.now()}")

        if not self.rejoin_failure:
            logger().info(f"Enabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    "rejoin_max_retry": 0,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init']) #'load_default_fw',
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
#@pytest.mark.firmware_app("wifitest")
def test_fw_upgrade_UART_C19376(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):

    testcase = "test_fw_upgrade_UART_C19376"
    logger().info(f"testcase : {testcase}")
    wifi_dut.interfaces.wifi.init()

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"dut ip : {device_ip}")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"
    logger().info("Ping is successful")
    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    "rejoin_max_retry": 0,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"]) #,"load_default_fw"])
def test_fw_upgrade_wireless_SPI_C19377(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):

    testcase = "test_fw_upgrade_wireless_SPI_C19377"
    logger().info(f"testcase : {testcase}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"Found device ip : {device_ip}")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg,alert_msg
    time.sleep(10)
    wifi_dut.interfaces.wifi.reset_soft()
    #wifi_dut.interfaces.wifi.wireless_deinit()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    "rejoin_max_retry": 40,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_fw_upgrade_wireless_in_rejoin_C19379(wifi_sniffer, wifi_dut, wifi_access_point, wiseconnect_web):

    testcase = "test_fw_upgrade_wireless_in_rejoin_C19379"
    logger().info(f"testcase: {testcase}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=40, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"found device ip : {device_ip}")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    rejoin_failure = False
    ap_off_thread = ApWirelessOff(wifi_access_point,wifi_dut, 20,rejoin_failure)
    ap_off_thread.start()
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg,\
        f"Firmware upgrade is not resumed after rejoin got error msg:{alert_msg}"
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    "rejoin_max_retry": 10,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_fw_upgrade_wireless_rejoin_failure_C19380(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    testcase = "test_fw_upgrade_wireless_rejoin_failure_C19380"
    logger().info(f"testcase : {testcase}")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=10, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
    time.sleep(2)

    for i in range(0,2):
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"found device ip :{device_ip}")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device before store configuration"

        current_version = wifi_dut.interfaces.wifi.version()
        logger().info(f"Current version: {current_version}")
        wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
        rejoin_failure = True

        if i == 0:
            ap_off_thread = ApWirelessOff(wifi_access_point, wifi_dut, 20, rejoin_failure)
            ap_off_thread.start()
        # configures the values from harness on given ip address of web page
        alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
            ip_address=device_ip, upgrade_wait_time=300)
        logger().info(f"upgraded message: {alert_msg}")
        if i == 0:
            time.sleep(90)
            logger().info(f"Enabling Wireless in AP")
            wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(20)
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.SSL,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem",
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_fw_upgrade_wireless_HTTPS_C19381(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    testcase = "test_fw_upgrade_wireless_HTTPS_C19381"
    logger().info(f"testcase : {testcase}")

    logger().info("This testcase will fail ,see issue RSC-8849")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)

    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, upgrade_wait_time=300,use_https=True)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg, alert_msg
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1}
)
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
def test_Wireless_fw_upgradein_AP_mode_C19378(wifi_sniffer, wifi_dut, wifi_client,wiseconnect_web):

    testcase = "test_Wireless_fw_upgradein_AP_mode_C19378"
    logger().info(f"testcase : {testcase}")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_client.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    time.sleep(20)
    logger().info(f"AP ip : {wifi_client.interfaces.wifi.client_gateway_ip}")
    status = ping(wifi_client.interfaces.wifi.client_gateway_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    #configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=wifi_client.interfaces.wifi.client_gateway_ip, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg, alert_msg
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("sniffer capture stopped")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    "rejoin_max_retry": 0,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_While_upgrading_Fw_close_TCP_connection_C19382(wifi_sniffer,wifi_dut,wifi_access_point, wiseconnect_web,wifi_client, net_perf_client,protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    logger().info("testcase : test_While_upgrading_Fw_close_TCP_connection_C19382")

    testcase = "test_While_upgrading_Fw_close_TCP_connection_C19382"
    logger().info(f"testcase : {testcase}")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,timeout=50)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"
    #
    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, upgrade_wait_time=20)
    logger().info(f"upgraded message: {alert_msg}")
    time.sleep(10)
    logger().info("waiting for RSI_FWUP_RSP_FAILED")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    # starting iperf as Client
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip)
    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj,net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None,"Throughput not found"
    __print_throughput(tp)

    logger().info("UDP RX data transfer is successful")
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    wifi_dut.interfaces.wifi.init()
    logger().info("Initialization successful")
    wifi_dut.interfaces.wifi.associated = False
    logger().info("Initiating join")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"device ip found : {device_ip}")
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, upgrade_wait_time=20)
    logger().info(f"upgraded message: {alert_msg}")
    logger().info("waiting for RSI_FWUP_RSP_FAILED")
    time.sleep(10)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None,"Throughput not found"
    __print_throughput(tp)
    logger().info("UDP TX data transfer is successful")

    #wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    wifi_dut.interfaces.wifi.init()
    wifi_dut.interfaces.wifi.associated = False
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    logger().info("Initiating disconnect from DUT")
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()

