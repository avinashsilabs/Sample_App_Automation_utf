from utf.utils.logger import get_logger
import pytest
from utf.utils.iperf.iperf_utils import ping
import time
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap
)
from utf.interfaces.wifi import WlanError

def logger():
    return get_logger(__name__)

# configure ping_count to ping dut
ping_count = 10

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

     Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content

    Author: Ravi Nemali

"""

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
@pytest.mark.http_client("raspi_http_client")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# This test cases verifies the https get with the linux as server and client
def test_http_server_and_linux_client_get(
    http_server, http_client, logger
):
    method = "GET"
    index_path = "index.html"
    # content = {"example": "data"}
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path
    )
    logger.info(status)
    logger.info(resp_content)

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_C19209(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("Initiates scan in dut")
    wifi_dut.interfaces.wifi.scan(ssid=None)

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enabling  bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data on https using post method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the https data"
    assert status1, "failed to load the https data"

    logger().info(status)
    logger().info(content)
    assert content == content1,"fetched data is not same as expected data"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_feature_not_enabled_dut_C19204(http_server, wifi_dut,http_client, wifi_access_point,index_path):

    logger().info("Initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure, no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching data on https using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert exc_info.value.error_code == 0xFF74, "observed wrong error code expected is 0xFF74"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_not_loading_cert_C19203(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure, no ap found"
    wifi_dut.interfaces.wifi.clear_certificate(cert_type=3,cert_index=0)
    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching https data using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert exc_info.value.error_code == 0xBBD2, "observed wrong error code expected is 0xBBD2"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html","index_long_crlf.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_different_urls_C19205(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure,no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching  https data using get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)
    assert content == content1, "fetched data is not same as expected data"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_send_100mbfile_from_peer_C19206(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching https data using get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger().info(status)
    logger().info(content)
    assert content == content1, "fetched data is not same as expected data"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
#This test case verifies the Https Get functionality by comparing the data and, by issuing invalid IP
def test_https_get_functionality_invalid_ip(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching https data using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http,index_path, server_ip='192.168.9.99')
    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_port10_C19207_case1(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetches https data using get method")
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=10)
    logger().info(status)
    logger().info(content)
    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_port200_C19207_case2(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    wifi_dut.interfaces.wifi.scan(ssid=None)

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetches https data using get method")
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=200)
    logger().info(status)
    logger().info(content)
    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_port2000_C19207_case3(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps,"failed to enable bt power save"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching https data using get method")
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=2000)
    logger().info(status)
    logger().info(content)
    assert status, "failed to fetch the https data"
    assert content, "failed to load the https data"

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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_functionality_port20000_C19207_case4(http_server, wifi_dut,http_client, wifi_access_point, index_path):

    logger().info("initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results,"scan failure,no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    logger().info("Enabling wifi power save")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_wifi_ps,"failed to enable wifi power save"

    logger().info("Enabling bt power save")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching https data using get method")
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port = 3343)
    logger().info(status)
    logger().info(content)
    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"