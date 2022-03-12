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




def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


#this thread is used for AP power ON/OFF
class ApWirelessOff:
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
            time.sleep(5)
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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19377(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    testcase = "test_Upgradation_through_Wireless_interface_in_station_mode_in_SPI"
    logger().info(f"testcase : {testcase}")

    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path= firmware_path, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg,alert_msg
    wifi_dut.reset()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()





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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19379(wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    testcase = "While_upgrading_Firmware_through_wireless_in_rejoin_case"
    logger().info(f"testcase: {testcase}")

    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    rejoin_failure = False
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point,wifi_dut, 20,rejoin_failure), )
    thread.start()
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path=firmware_path, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg, alert_msg
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")



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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19380(wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'
    testcase = "While_upgrading_Firmware_through_wireless_power_off_AP_and_wait_until_get_rejoin_failure"
    logger().info(f"testcase : {testcase}")

    for i in range(0,2):
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        status = ping(device_ip, 10)
        assert status is True, "DUT is not responding to ping request from third party device before store configuration"

        current_version = wifi_dut.interfaces.wifi.version()
        logger().info(f"Current version: {current_version}")
        wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
        rejoin_failure = True

        if i == 0:
            thread = Thread(target=ApWirelessOff, args=(wifi_access_point,wifi_dut, 20,rejoin_failure), )
            thread.start()
        # configures the values from harness on given ip address of web page
        alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
            ip_address=device_ip, firmware_file_path=firmware_path, upgrade_wait_time=300)
        logger().info(f"upgraded message: {alert_msg}")
        if i == 0:
            time.sleep(90)
            logger().info(f"Enabling Wireless in AP")
            wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(20)
    wifi_dut.interfaces.wifi.reset_soft()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPSServer | RS9116TCPIPFeatureBitMap.SSL,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        #"ca_cert": "ca-chain.cert.pem",
        "server_cert": "mosquitto-utf.silabs.com.cert.pem",
        "server_key": "mosquitto-utf.silabs.com.key.pem",
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19381(wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )
    testcase = "test_Firmware_upgrade_using_HTTPs_server"
    logger().info(f"testcase : {testcase}")

    logger().info("This testcase will fail ,see issue RSC-8849")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)

    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path=firmware_path, upgrade_wait_time=300,use_https=True)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg, alert_msg
    wifi_dut.reset()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")
    wifi_sniffer.interfaces.capture.stop_capture()
#


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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19382_1(wifi_sniffer,wifi_dut,wifi_access_point, wiseconnect_web,wifi_client, net_perf_client,protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    logger().info("testcase : While_upgrading_Firmware_through_wireless_close_the_TCP_connection_and_verify_firmware_upgrade_functionality")

    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'

    testcase = "test_C19382_1"
    logger().info(f"testcase : {testcase}")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,timeout=50)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"
    #
    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path= firmware_path, upgrade_wait_time=10)
    logger().info(f"upgraded message: {alert_msg}")
    logger().info("RSI_FWUP_RSP_FAILED")
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
    assert tp is not None
    __print_throughput(tp)

    logger().info("UDP data transfer is successful")
    wifi_dut.reset()
    logger().info("*************Need to add de init functionality instead of reset*********")
    wifi_dut.interfaces.wifi.set_state("init")
    wifi_dut.interfaces.wifi.associated = False
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    wifi_sniffer.interfaces.capture.stop_capture()



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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19382_2(wifi_sniffer,wifi_dut,wifi_access_point, wiseconnect_web,wifi_client, net_perf_client,protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError(
            "This test case is only currently implemented for SAPI"
        )

    logger().info("testcase : While_upgrading_Firmware_through_wireless_close_the_TCP_connection_and_verify_firmware_upgrade_functionality")

    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'

    testcase = "test_C19382_2"
    logger().info(f"testcase : {testcase}")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point,timeout=50)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device before store configuration"

    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    # configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=device_ip, firmware_file_path= firmware_path, upgrade_wait_time=10)
    logger().info(f"upgraded message: {alert_msg}")
    logger().info("RSI_FWUP_RSP_FAILED")
    #input()
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
    assert tp is not None
    __print_throughput(tp)
    logger().info("UDP data transfer is successful")
    wifi_dut.reset()
    logger().info("*************Need to add de init functionality instead of reset*********")
    wifi_dut.interfaces.wifi.set_state("init")
    wifi_dut.interfaces.wifi.associated = False
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    wifi_sniffer.interfaces.capture.stop_capture()


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
@pytest.mark.start_state("wifi_dut", wifi=['reset','init'])
@pytest.mark.config("wifi_client", wifi={"interface": "wlan0"})
def test_C19378(wifi_dut, wifi_client,wiseconnect_web):

    testcase = "Up_gradation_through_Wireless_interface_in_AP_mode"
    logger().info(f"testcase : {testcase}")
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    time.sleep(20)
    logger().info(f"AP ip : {wifi_client.interfaces.wifi.client_gateway_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip) < 0.1
    firmware_path = '/app/manifest/RS9116W.2.4.1.17.rps'
    current_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Current version: {current_version}")
    wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
    #configures the values from harness on given ip address of web page
    alert_msg = wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
        ip_address=wifi_client.interfaces.wifi.client_gateway_ip, firmware_file_path= firmware_path, upgrade_wait_time=300)
    logger().info(f"upgraded message: {alert_msg}")
    assert "Firmware Upgraded Successfully" in alert_msg, alert_msg
    wifi_dut.reset()
    logger().info("*************Need to add de init functionality instead of reset*********")
    time.sleep(90)
    wifi_dut.interfaces.wifi.wireless_init()
    upgraded_version = wifi_dut.interfaces.wifi.version()
    logger().info(f"Upgraded version: {upgraded_version}")

