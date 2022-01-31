import time
import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    )
from utils.iperf.iperf_utils import get_host_ip
from interfaces.wifi import WlanError
from utils.logger import get_logger

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
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
# verifies the otaf failure with only BT mode with error code 0x21
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_https_fw_upgrade_failure_when_enabled_only_bt_C19774(http_server, wifi_dut, wifi_access_point, logger):
    host_ip = get_host_ip()
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    time.sleep(10)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
# verifies the otaf failure with only BT mode with error code 0x21
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_https_fw_upgrade_failure_when_enabled_only_ble_C19774(http_server, wifi_dut, wifi_access_point, logger):
    host_ip = get_host_ip()
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    time.sleep(10)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
# verifies the otaf failure with only BT mode with error code 0x21
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_https_fw_upgrade_failure_when_enabled_only_dual_bt_C19774(http_server, wifi_dut, wifi_access_point, logger):
    host_ip = get_host_ip()
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    time.sleep(10)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"


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
# verifies the otaf failure with Wlan only mode and a non-rps file with error code 0xBB41
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_https_fw_upgrade_failure_when_enabled_only_bt_C19776(http_server, wifi_dut, wifi_access_point, logger):
    # Joins the access point
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()
    host_ip = get_host_ip()
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    time.sleep(10)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.txt")
    assert exc_info.value.error_code == 0xFFFD , "observed wrong error code expected is 0xFFFD"