import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116AsyncEventType
    )
from utf import UtfDatabaseProperties
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from utf.interfaces.wifi import WlanError
import time
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

"""
     Setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http firmware upgrade
        5. Verify the otaf status

    Author: RaviNemali && Benazeer K
"""

# Otaf timeout for deinit
timeout = 60


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
                              | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_over_night_C19771(http_server, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    time_duration = utf_constants.get("time_duration")
    sw = Stopwatch()
    logger().info(f"Time duration is {time_duration} Mins")
    while sw.elapsed_sec < time_duration:
        """ ******* SERVER CHECKS ******* """
        logger().info("Verifying server stats....")
        server_stat = http_server.interfaces.http.started
        assert server_stat == True,"server is inactive"
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
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_https_fw_upgrade_over_night_C19771')

        logger().info("dut fw version before upgrade...")
        fw_before_upgrade = wifi_dut.interfaces.wifi.version()

        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
        assert len(scan_results) > 0, "scan_list not found"

        logger().info("Joining the ap....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("Starting dhcp....")
        wifi_dut.interfaces.wifi.start_ip()

        start_time = time.perf_counter_ns()
        async_timestamp = 0
        time.sleep(2)

        logger().info("Performing firmware upgrade....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
        time.sleep(120)

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
            time_duration_taken = (async_timestamp - start_time) / 1000000000
            logger().info(f"Time taken to upgrade firmware using http otaf {time_duration_taken} seconds")

        # assert time_duration_taken < 125, "took too long time to download fw"

        if time_duration_taken > 45:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration_taken}")
        else:
            logger().info(f"Time taken to upgrade firmware using http otaf {time_duration_taken} seconds")

        time.sleep(5)
        logger().info("resetting DUT....")
        wifi_dut.interfaces.wifi.wireless_deinit(timeout=timeout)
        time.sleep(10)

        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.init(reset_type="rs911x")

        wifi_dut.interfaces.wifi.associated = False

        logger().info("fetching the fw version after init....")
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        time.sleep(2)
        if fw_before_upgrade == fw_after_upgrade:
            logger().info(f"before and after upgradations matched")
        else:
            assert "firmwares versions are not matched"

        logger().info("Stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
                              | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_corrupted_rps_over_night_C19772(http_server, wifi_dut, wifi_access_point, wifi_sniffer,
                                                          utf_constants):
    time_duration = utf_constants.get("time_duration")
    sw = Stopwatch()
    logger().info(f"Time duration is {time_duration} Mins")
    while sw.elapsed_sec < time_duration:
        """ ******* SERVER CHECKS ******* """
        logger().info("checking weather server is running....")
        server_stat = http_server.interfaces.http.started
        assert server_stat == True,"server is inactive"
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_corrupted_rps_over_night_C19772')

        logger().info("dut fw version before upgrade...")
        fw_before_upgrade = wifi_dut.interfaces.wifi.version()

        logger().info("joining ap....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("starting dhcp....")
        wifi_dut.interfaces.wifi.start_ip()

        logger().info("performing fw upgrade on dut with corrupted rps....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4_corrupted.rps")
        time.sleep(40)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.get_http_otaf_status()
        assert exc_info.value.error_code == 0xBB41 | 0xFFFD, "observed wrong error code expected is 0xBB41"

        time.sleep(5)
        logger().info("resetting DUT....")
        wifi_dut.interfaces.wifi.wireless_deinit(timeout=timeout)
        time.sleep(10)

        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.init(reset_type="rs911x")

        wifi_dut.interfaces.wifi.associated = False

        logger().info("fetching the fw version after init....")
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        if fw_before_upgrade == fw_after_upgrade:
            logger().info(f"before and after upgradations matched")
        else:
            assert "firmwares versions are not matched"

        logger().info("stop Sniffer capture...")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
                              | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_non_rps_over_night_C19773(http_server, wifi_dut, wifi_access_point, wifi_sniffer,
                                                    utf_constants):
    time_duration = utf_constants.get("time_duration")
    sw = Stopwatch()
    logger().info(f"Time duration is {time_duration} Mins")
    while sw.elapsed_sec < time_duration:
        """ ******* SERVER CHECKS ***** """
        logger().info("checking server stats....")
        server_stat = http_server.interfaces.http.started
        assert server_stat == True,"server is inactive"
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_non_rps_over_night_C19773')

        logger().info("dut fw version before upgrade...")
        fw_before_upgrade = wifi_dut.interfaces.wifi.version()

        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
        assert len(scan_results) > 0, "scan_list not found"

        logger().info("Joining ap....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("configuring dhcp...")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'device ip {device_ip}')

        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/cgi-bin/cgi_example.py")
        time.sleep(10)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.get_http_otaf_status()
            time.sleep(10)
        assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD"

        time.sleep(5)
        logger().info("resetting DUT....")
        wifi_dut.interfaces.wifi.wireless_deinit(timeout=timeout)
        time.sleep(10)

        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.inited = False
        wifi_dut.interfaces.wifi.init(reset_type="rs911x")

        wifi_dut.interfaces.wifi.associated = False

        logger().info("Fetching the DUT version...")
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        if fw_before_upgrade == fw_after_upgrade:
            logger().info(f"before and after upgradations matched")
        else:
            assert "firmwares versions are not matched"

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)
