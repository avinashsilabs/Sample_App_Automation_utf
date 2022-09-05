import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116AsyncEventType,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116OperatingMode,
    RS9116Band,
    RS9116PowerSaveModes
)
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

"""
     setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate https firmware upgrade
        5. Verify the https otaf status

    Author: RaviNemali
"""

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_fw_upgrade_failure_when_STA_is_not_connected_C19757(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("Verifying server stats...")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()
    logger().info(f"host ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_fw_upgrade_failure_when_STA_is_not_connected_C19757')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("scanning for ap...")
    wifi_dut.interfaces.wifi.scan(ssid=None)

    with pytest.raises(WlanError) as exc_info:
        logger().info("Performing firmware upgrade....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
        time.sleep(10)
    assert exc_info.value.error_code == 0x0021, "observed wrong error code expected is 0x0021"
    time.sleep(10)

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_STA_alone_mode_and_measure_time_C19758(http_server, wifi_dut, wifi_access_point,wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("Verifying server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_STA_alone_mode_and_measure_time_C19758')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining the ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("Performing firmware upgrade....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("Fetching the otaf status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching the fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_STA_BT_mode_and_measure_time_C19759(http_server, wifi_dut, wifi_access_point,wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_STA_BT_mode_and_measure_time_C19759')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("Performing firmware upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("fetching the otaf uprade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching dut version after init....")
    wifi_dut.interfaces.wifi.version()

    time.sleep(10)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_STA_BLE_mode_and_measure_time_C19760(http_server, wifi_dut, wifi_access_point,wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_STA_BLE_mode_and_measure_time_C19760')

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("Performing fw upgrade on DUT....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching DUT version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_STA_BT_BLE_mode_and_measure_time_C19761(http_server, wifi_dut, wifi_access_point,wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with S(niffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_STA_BT_BLE_mode_and_measure_time_C19761')

    logger().info("Fetching DUT fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("joining ap.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("upgrading firmware......")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("fetching otaf status...")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.skip(reason="skipped as it is removed from test rail")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11g'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_otaf_ap_11g_testcase7(http_server, wifi_dut, wifi_access_point):
    logger().info(" joinig ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT fw version ...")
    wifi_dut.interfaces.wifi.version()

    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(50)

    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    logger().info("Fetching the DUT fw version after upgrade...")
    wifi_dut.interfaces.wifi.version()

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.skip(reason= "skipped as it is removed from test rail")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11g'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_otaf_ap_11n_testcase8(http_server, wifi_dut, wifi_access_point):
    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT fw version ...")
    wifi_dut.interfaces.wifi.version()

    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(50)

    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    logger().info("Fetching the DUT fw version after upgrade...")
    wifi_dut.interfaces.wifi.version()

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_UART_mode_and_measure_time_C19767(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_UART_mode_and_measure_time_C19767')

    logger().info("Fetching the DUT version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("fetching upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.skip(reason="skipped as it is removed from test rail")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_ps_mode_and_measure_time_C19768(http_server, wifi_dut, wifi_access_point):
    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("configuring dut in wlan power save mode....")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("configuring dut in bt power save mode....")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("fetching host ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT fw version...")
    wifi_dut.interfaces.wifi.version()

    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(50)

    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    logger().info("Fetching the DUT fw version after upgrade...")
    wifi_dut.interfaces.wifi.version()

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_Q7_board_and_measure_time_C19770(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    logger().info("Verifying server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_Q7_board_and_measure_time_C19770')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining the ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("Performing firmware upgrade....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("Fetching the otaf status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching the fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_with_empty_rps_C19778(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_failure_with_empty_rps_C19778')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting ap....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("performing fw upgrade on dut with empty rps file....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4_empty.rps")
    time.sleep(40)
    with pytest.raises(WlanError) as exc_info:
        logger().info("fetching otaf status...")
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xBBE2, "observed wrong error code expected is 0xBBE2"

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_with_junk_rps_C19775(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_failure_with_junk_rps_C19775')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("performing fw upgrade on dut with corrupted rps....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4_corrupted.rps")
    time.sleep(40)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xBB41 | 0xfffd, "observed wrong error code expected is 0xBB41"

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching the fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_without_enabling_http_C19777(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_failure_without_enabling_http_C19777')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xFF74, "observed wrong error code expected is 0xff74"
    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "band": 2,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_in_A7_board_and_measure_time_C19770(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ******* """
    logger().info("Verifying server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_in_A7_board_and_measure_time_C19770')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Joining the ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    logger().info("Performing firmware upgrade....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)

    logger().info("Fetching the otaf status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    logger().info("fetching the otaf async events after the upgrade....")
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    time.sleep(5)
    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    logger().info("fetching the fw version after init....")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer capture...")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)

@pytest.mark.firmware_app("test_concurrent_mode")
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.ConcurrentMode,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DHCPv4Server
                          | RS9116TCPIPFeatureBitMap.Ping | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
                              | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORDBIT,
        "band": RS9116Band.Default,
        "ca_cert": "ca-chain.cert.pem",
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 1,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 1}
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_http_fw_upgrade_in_conc_mode_and_measure_time_C19762(firmware_loader, http_server, wifi_sniffer,
                                                              wifi_dut, wifi_access_point, wifi_client):
    """ ******* SERVER CHECKS ******* """
    ping_count = 10
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")

    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_http_fw_upgrade_in_conc_mode_msure_time_C19762')
    logger().info("preparing wifi_dut as access point - AP Mode")

    logger().info("checking weather server is running....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0
    logger().info(f"server ip is {host_ip}")
    #
    logger().info("pinging to server ip....")
    status = ping(host_ip, ping_count)
    assert status == 1, "unable to ping to server"

    # validation = True
    ping_iterations = 10
    wifi_dut.interfaces.wifi.associated = False

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f'ap mac is {dut_mac_address}')

    ap_mac = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'ap mac is {ap_mac}')

    logger().info("Bringing up DUT in AP mode")
    wifi_dut.interfaces.wifi.start_ap()

    logger().info("joining 3rd party client to DUT ap")
    wifi_client.interfaces.wifi.join()

    logger().info("fetching gateway ip of ap")
    device_ip_dut_as_ap = wifi_client.interfaces.wifi.client_gateway_ip

    logger().info("fetching p address of 3rd party sta")
    wifi_client_ip = wifi_client.interfaces.wifi.get_ip_address()
    status = ping(wifi_client_ip, ping_iterations)
    assert status == 1
    logger().info("dut ap mode ip: " + device_ip_dut_as_ap)
    logger().info("wifi client ip: " + str(wifi_client_ip))

    # preparing wifi_dut as STA - STA Mode
    logger().info("joining to 3rd party AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info("fetching ip address through DHCP")
    ip_config = wifi_dut.interfaces.wifi.start_ip(vap_id=1)
    device_ip_dut_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    wifi_dut.interfaces.wifi.ping(server_ip=acces_point_ip)

    logger().info("DUT Station Mode")
    logger().info("dut station mode ip: " + device_ip_dut_as_client)
    logger().info("access point ip: " + str(acces_point_ip))

    # performs the firmware upgrade on DUT over the http port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    time.sleep(40)
    ping(wifi_client_ip, ping_iterations)
    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit()
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()
    time.sleep(10)

    # gets DUT fw version
    logger().info("fetching fw version after init....")
    wifi_dut.interfaces.wifi.version()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")