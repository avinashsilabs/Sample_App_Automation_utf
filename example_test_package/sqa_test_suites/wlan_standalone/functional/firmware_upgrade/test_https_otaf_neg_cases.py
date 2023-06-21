import time
import pytest
from utf import UtfDatabaseProperties
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
        "coex_mode": RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "skip_radio_init": True
    },
)
@pytest.mark.bt_classic
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_when_enabled_only_bt_C19774(http_server, wifi_dut, wifi_access_point):
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True, "server is inactive"
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
        "coex_mode": RS9116CoexMode.BLE,
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
def test_https_fw_upgrade_failure_when_enabled_only_ble_C19774(http_server, wifi_dut):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True, "server is inactive"
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
@pytest.mark.bt_classic
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_https_fw_upgrade_failure_when_enabled_only_dual_bt_C19774(http_server, wifi_dut):
    """ ******* SERVER CHECKS ******* """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat == True, "server is inactive"
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
def test_https_fw_upgrade_failure_with_non_rps_C19776(http_server, wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                      utf_constants):
    """ ******* SERVER CHECKS ***** """
    logger().info("checking server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat, "server is inactive"
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching server ip....")
    host_ip = http_server.interfaces.http.hostname_or_ip_address
    logger().info(f"server ip is {host_ip}")

    logger().info("pinging to server ip....")
    status = ping(host_ip, 10)
    assert status, "unable to ping to server"

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_fw_upgrade_failure_with_non_rps_C19776')

    logger().info("dut fw version before upgrade...")
    wifi_dut.interfaces.wifi.version()
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point,
                                                                   power_save=False)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    logger().info("performing fw upgrade on dut by removing data in .xls file....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "RS9116.2.5.0.4_remove.xls")

    time.sleep(120)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD"

    logger().info("performing fw upgrade on dut by adding data in .xls file....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "RS9116.2.5.0.4_add.xls")

    time.sleep(120)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xBB41, "observed wrong error code expected is 0xBB41"

    time.sleep(5)
    logger().info("Initiating wireless_deinit from DUT....")
    wifi_dut.interfaces.wifi.wireless_deinit(timeout=timeout)
    time.sleep(10)

    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(reset_type="rs911x")
    wifi_dut.interfaces.wifi.associated = False

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(10)



