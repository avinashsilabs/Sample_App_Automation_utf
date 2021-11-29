from utils.logger import get_logger
import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap
)
from interfaces.wifi import WlanError

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
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
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
#This test case verifies the Https Get functionality for different lengths of url's
def test_http_get_with_different_lengths(http_server,http_client, wifi_dut, wifi_access_point, logger, index_path):

    # Initiates scan in dut
    wifi_dut.interfaces.wifi.scan(ssid=None)

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # starts the dhcp in dut
    wifi_dut.interfaces.wifi.start_ip()

    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the http data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger.info(status)
    logger.info(content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
#This test case verifies the Https Get functionality, when invalid IP is provided
def test_http_get_with_invalid_IP(http_server, wifi_dut, wifi_access_point, logger, index_path):

    # Initiates scan in dut
    wifi_dut.interfaces.wifi.scan(ssid=None)

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # starts the dhcp in dut
    wifi_dut.interfaces.wifi.start_ip()

    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the http data
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_ip= '192.168.9.99')
    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
#This test case verifies the Https Get functionality, for 100 mb file
def test_http_get_with_100_mb_file(http_server, wifi_dut, wifi_access_point, logger, index_path):

    # Initiates scan in dut
    wifi_dut.interfaces.wifi.scan(ssid=None)

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # starts the dhcp in dut
    wifi_dut.interfaces.wifi.start_ip()

    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the http data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_crlf.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
#This test case verifies the Https Get functionality by comparing the data and, by issuing the get response with host name
def test_http_get_functionality_comparison(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

    # Initiates scan in dut
    wifi_dut.interfaces.wifi.scan(ssid=None)

    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # starts the dhcp in dut
    wifi_dut.interfaces.wifi.start_ip()

    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the http data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger.info(status)
    logger.info(content)
    assert content == content1







