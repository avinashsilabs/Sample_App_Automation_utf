from utils.logger import get_logger
import pytest
import time
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
#This test case verifies the Https Get functionality by comparing the data and, by issuing the get response with host name
def test_https_get_functionality(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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
#This test case verifies the Https Get functionality by comparing the data and, by not enabling the feature in dut
def test_https_get_functionality_feature_not_enabled_dut(http_server, wifi_dut,http_client, wifi_access_point,
                                                         logger, index_path):

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

    # API used to get the https data
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
#This test case verifies the Https Get functionality by comparing the data and, by not loading cert in dut
def test_https_get_functionality_not_loading_cert(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

    # Initiates scan in dut
    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.clear_certificate(cert_type=3,cert_index=0)
    # Joins the access point with given ssid and the passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # starts the dhcp in dut
    wifi_dut.interfaces.wifi.start_ip()

    # Enables the wifi power save in dut
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables the bt power save in dut
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the https data
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
#This test case verifies the Https Get functionality by comparing the data and, by issuing different urls
def test_https_get_functionality_different_urls(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger.info(status)
    logger.info(content)
    assert content == content1

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
#This test case verifies the Https Get functionality by comparing the data and, by 100mb file
def test_https_get_functionality_send_100mbfile_from_peer(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger.info(status)
    logger.info(content)
    assert content == content1

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
#This test case verifies the Https Get functionality by comparing the data and, by issuing invalid IP
def test_https_get_functionality_invalid_ip(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
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
#This test case verifies the Https Get functionality by comparing the data and, by issuing port number as 10
def test_https_get_functionality_port10(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=10)
    logger.info(status)
    logger.info(content)

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
#This test case verifies the Https Get functionality by comparing the data and, by issuing port number as 200
def test_https_get_functionality_port200(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=200)
    logger.info(status)
    logger.info(content)

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
#This test case verifies the Https Get functionality by comparing the data and, by issuing port number as 200
def test_https_get_functionality_port2000(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=2000)
    logger.info(status)
    logger.info(content)

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
#This test case verifies the Https Get functionality by comparing the data and, by issuing port number as 20000
def test_https_get_functionality_port20000(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):

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

    # API used to get the https data
    status, content= wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,port=20000)
    logger.info(status)
    logger.info(content)