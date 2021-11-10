import time
import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116AsyncEventType,
    RS9116PowerSaveModes
    )
from utils.iperf.iperf_utils import get_host_ip
from interfaces.wifi import WlanError
from utils.logger import get_logger


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
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade failure in DUT over the https connection on providing the empty rps file
def test_https_otaf_sta_unassociated_testcase1(http_server, wifi_dut, wifi_access_point, logger):
    # This API gets the host ip for the http server
    host_ip = get_host_ip()

    # performs the soft reset on DUT
    wifi_dut.interfaces.wifi.reset_soft()

    # DUT wifi initialization
    wifi_dut.interfaces.wifi.init()
    with pytest.raises(WlanError) as exc_info:
        # performs the firmware upgrade on DUT over the https port
        wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    assert exc_info.value.error_code == 0x0021, "observed wrong error code expected is 0x0021"

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection in wlan mode
def test_https_otaf_testcase2(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)
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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN |RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection in wlan and bluetooth mode
def test_https_otaf_wifi_bt_testcase3(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN |RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection in wlan and BLE mode
def test_https_otaf_wifi_bt_testcase4(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection in wlan and dual bluetooth mode
def test_https_otaf_wifi_bt_testcase5(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)
    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()
    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config('wifi_access_point',wifi ={"standard": '11g'})
# These test case verifies the firmware upgrade in DUT over the https connection on DUT connection in access point 11g mode
def test_http_otaf_ap_11g_testcase7(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config('wifi_access_point',wifi ={"standard": '11g'})
# These test case verifies the firmware upgrade in DUT over the https connection on DUT connection in access point 11n mode
def test_http_otaf_ap_11n_testcase8(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection on DUT SPI connection
def test_https_otaf_usb_spi_interface_testcase11(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection by enabling the power save mode in DUT
def test_https_otaf_ap_power_save_testcase12(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # Enables wifi power save on DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Enables bt power save on DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection on single band Q7 board
def test_https_otaf_Q7_board_testcase14(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
        "band":1,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade in DUT over the https connection on dual band A7 board
def test_https_otaf_A7_board_testcase14(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    time.sleep(60)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

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
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade failure in DUT over the https connection on providing the empty rps file
def test_https_otaf_empty_neg_testcase5(http_server, wifi_dut, wifi_access_point, logger):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4_empty.rps")
    time.sleep(30)
    with pytest.raises(WlanError) as exc_info:
        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xbbe2

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade failure in DUT over the https connection on providing the corrupted rps file
def test_https_otaf_corrupted_firmware_neg_testcase2(http_server, wifi_dut, wifi_access_point, logger):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4_corrupted.rps")
    time.sleep(60)
    with pytest.raises(WlanError) as exc_info:
        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xfffd, "observed wrong error code expected is 0xFFFD"

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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.http_server("raspi_lighttpd_tls")
# These test case verifies the firmware upgrade failure in DUT over the https connection,when http is disabled in DUT
def test_https_otaf_feature_not_enabled_neg_testcase4(http_server, wifi_dut, wifi_access_point, logger):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()

    # performs the firmware upgrade on DUT over the https port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(2, host_ip, 443, "/RS9116.2.5.0.4.rps")
    with pytest.raises(WlanError) as exc_info:
        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xff74, "observed wrong error code expected is 0xff74"



