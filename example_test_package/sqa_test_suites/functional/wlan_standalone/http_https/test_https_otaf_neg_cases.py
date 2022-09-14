import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
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
        1 : Configuration of DUT in BT/Wlan in 2.4Ghz
        2 : Verify the connection to AP
        3 : Verify the host IP for firmware upgrade
        4 : Initiate the firmware upgrade (otaf) in dut
        5 : Verify weather the otaf is successful or failed with the issue/error 

    Author: Ravinemali  
"""

# Otaf timeout for deinit
timeout = 60

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "skip_radio_init": True
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_when_enabled_only_bt_C19774(http_server, wifi_dut, wifi_access_point):
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

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "skip_radio_init": True
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_when_enabled_only_ble_C19774(http_server, wifi_dut, wifi_access_point):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "skip_radio_init": True
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_when_enabled_only_dual_bt_C19774(http_server, wifi_dut, wifi_access_point):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = get_host_ip()
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status == 1, "unable to ping to server"

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443)
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_with_non_rps_C19776(http_server, wifi_dut, wifi_access_point, wifi_sniffer):
    """ ******* SERVER CHECKS ***** """
    logger().info("checking server stats....")
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
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_failure_with_non_rps_C19776')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()

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
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.xml")
    time.sleep(10)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_http_otaf_status()
        time.sleep(10)
    assert exc_info.value.error_code == 0xBBE2, "observed wrong error code expected is 0xBBE2"

    # API does soft reset on DUT
    time.sleep(5)
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit(timeout=timeout)
    time.sleep(10)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.dut_init()

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)