import time
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    RS9116ConfigFeatureBitMap
)
from utf.interfaces.wifi import WlanError


def logger():
    return get_logger(__name__)


# configure this for looping the case
iter_count = 5
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html", "index_long_crlf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_with_different_lengths_C19213(http_server, http_client, wifi_dut, wifi_access_point, index_path):
    logger().info("scan for the devices")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results, "scan failure, No ap found"

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("start dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Enables the wifi power save in dut
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("enable bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from server bt get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_with_invalid_IP_C19212(http_server, wifi_dut, wifi_access_point, index_path):
    logger().info("Initiating scan in dut")
    scan_resuts = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_resuts, "scan failure, no ap found"

    logger().info("joining to access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starting dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("Enables the bt power save in dut")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from  http server using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_ip='192.168.9.99')

    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_with_100_mb_file_C19214(http_server, wifi_dut, wifi_access_point, index_path):
    logger().info(f"path{index_path}")
    logger().info("Initiates scan in dut")
    scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_result, "scan failure,no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("Enables the bt power save in dut")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the http data using get method")
    result = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert result, "fetched data is empty,failed to get data"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_crlf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_functionality_comparison_C19215(http_server, wifi_dut, http_client, wifi_access_point, index_path):
    logger().info("Initiates scan in dut")
    scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_result, "scan failure, no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    time.sleep(10)
    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("Enables the bt power save in dut")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetches the http data using get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger().info(status)
    logger().info(content)
    assert content == content1, "received data is not same as expected data"
    time.sleep(30)


# ================== HTTP Post test cases ====================

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_C19219(http_server, wifi_dut, http_client, wifi_access_point):
    logger().info("Initiates scan in dut")
    scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_result, "scan failure, no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enables the bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    assert enable_bt_ps, "failed to enable bt ps"

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellothisiaatestcaseforget")
    assert status, "failed to get http data"
    assert content, "failed to get http data"
    logger().info(status)
    logger().info(content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_for_50mb_data_C19222(http_server, wifi_dut, http_client, wifi_access_point):
    logger().info("Initiates scan in dut")
    scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_result, "scan failure,no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable power save"

    logger().info("Enables the bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellohvbsjvhkjsdhvhksdhvksjdvravvjvdhi"
                                                                   "jhdvbjhbjdhjvjdbjbsdwfbkjdhkdhfkk"
                                                                   "jhdvjdjhddjhjgfjhjfdkhfhhfkhjhkfhjkfhkhfhak")
    assert status, "failed to get http data"
    logger().info(status)
    logger().info(content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py", "index_long_crlf.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_different_urls_C19224(http_server, wifi_dut, http_client, wifi_access_point,
                                                       index_path):
    logger().info("Initiates scan in dut")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results, "scan failure, no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Enables the wifi power save in dut")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enables the bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable "

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("http functionality using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                         post_data="hellothisisfordifferenturlsusedtopostthed"
                                                                   "atoverthehttppostprotocol")
    assert status, "failed to post data to http server"
    logger().info(status)
    logger().info(content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
def test_http_post_functionality_for_5_iterations_C19221(http_server, wifi_dut, http_client, wifi_access_point):
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("Initiates scan in dut")
        scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
        assert scan_result, "scan failure,no ap found"

        logger().info("Joining access point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("starts the dhcp in dut")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("Enables the wifi power save in dut")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save "

        logger().info("Enables the bt power save in dut")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)

        assert enable_bt_ps, "failed to enable bt power save"
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        logger().info("sends data to http server using post method")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellotestingfrohttppostcontent")
        assert status, "failed to post data"
        logger().info(status)

        logger().info("disconnecting ap")
        wifi_dut.interfaces.wifi.leave()
    logger().info(content)
    logger().info(f"******************* iteration {count} completed ********************* ")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_invalid_ip_C19220(http_server, wifi_dut, http_client, wifi_access_point):
    logger().info("initiates scan in dut")
    scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_result, "sca failure, no ap found"

    logger().info("Joining access point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("starts the dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info("Enables the wifi power save in dut")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Enables the bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                           server_ip='192.168.9.99',
                                           post_data="hellothisisatestcase")
    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ca_cert": "ca_ecdsa.crt"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_get_with_wrong_certificate_C19211(http_server, wifi_sniffer, http_client, wifi_dut, wifi_access_point, index_path):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_get_with_wrong_certificate_C19211')
    time.sleep(3)
    logger().info("scan for the devices")
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    assert scan_results, "scan failure, No ap found"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("start dhcp in dut")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    # Enables the wifi power save in dut
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("enable bt power save in dut")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count1)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("fetching https data using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert exc_info.value.error_code == 0xBBD2, "observed wrong error code expected is 0xBBD2"

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_for_5_iterations_C19225(http_server, wifi_dut, http_client, wifi_access_point):
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("Initiates scan in dut")
        scan_result = wifi_dut.interfaces.wifi.scan(ssid=None)
        assert scan_result, "scan failure,no ap found"

        logger().info("Joining access point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("starts the dhcp in dut")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("Enables the wifi power save in dut")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save "

        logger().info("Enables the bt power save in dut")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)

        assert enable_bt_ps, "failed to enable bt power save"
        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        logger().info("sends data to http server using post method")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellotestingfrohttppostcontent")
        assert status, "failed to post data"
        logger().info(status)

        logger().info("disconnecting ap")
        wifi_dut.interfaces.wifi.leave()
    logger().info(content)
    logger().info(f"******************* iteration {count} completed ********************* ")
