import time
import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116AsyncEventType
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
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http firmware upgrade
        5. Verify the otaf status

    Author: RaviNemali
"""

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade failure in DUT over the http connection whe dut is not connected
def test_fw_upgrade_failure_when_STA_is_not_connected_C19779(http_server, wifi_dut, wifi_access_point):

    # This API gets the host ip for the http server
    logger().info(" fetching the host IP for http server")
    host_ip = get_host_ip()

    # performs the soft reset on DUT
    logger().info("Performing DUT reset...")
    wifi_dut.interfaces.wifi.reset_soft()

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # DUT wifi initialization
    logger().info("Initialising DUT....")
    wifi_dut.interfaces.wifi.init()
    with pytest.raises(WlanError) as exc_info:

        # performs the firmware upgrade on DUT over the http port
        logger().info("Performing firmware upgrade....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    assert exc_info.value.error_code == 0x0021, "observed wrong error code expected is 0x0021"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default

        },
    )

# These test case verifies the firmware upgrade in DUT over the http connection in wlan mode
def test_http_fw_upgrade_in_STA_alone_mode_and_measure_time_C19780(http_server, wifi_dut, wifi_access_point):

    # Joins the AP with given ssid and passphrase
    logger().info("Joing the ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching the host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("Performing firmware upgrade....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("Fetching the otaf status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("performing dut reset after reset....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching the fw version after init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection in wlan and bluetooth mode
def test_http_fw_upgrade_in_STA_BT_mode_and_measure_time_C19781(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host IP for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("Performing firmware upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching the otaf uprade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting DUT....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing DUT....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching dut version after init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection in wlan and BLE mode
def test_http_fw_upgrade_in_STA_BLE_mode_and_measure_time_C19782(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("Starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host IP for server....")
    host_ip = get_host_ip()
    time.perf_counter_ns()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("Performing fw upgrade on DUT....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting the DUT after upgrade....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(30)

    # performs the wifi initialization
    logger().info("Initializing DUT....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching DUT version aftre init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.BLE | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection in wlan and dual bluetooth mode
def test_http_fw_upgrade_in_STA_BT_BLE_mode_and_measure_time_C19783(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

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

    logger().info("Fetching the DUT fw version after upgrade...")
    wifi_dut.interfaces.wifi.version()

    # API does soft reset on DUT
    logger().info("resetting dut after upgrade....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing dut after reset....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection on DUT connection in access point 11g mode
@pytest.mark.config('wifi_access_point',wifi ={"standard": '11g'})
def test_http_otaf_ap_11g_mode(http_server, wifi_dut, wifi_access_point):
    logger().info("This Test case is not listed in test rail cases and automated from confluence")
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("fetching the otaf async events after the upgrade....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching the otaf async events after the upgrade....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on DUT....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf status after upgrade....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing DUT....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching dut version after init....")
    wifi_dut.interfaces.wifi.version()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
@pytest.mark.config('wifi_access_point',wifi ={"standard": '11n'})
# These test case verifies the firmware upgrade in DUT over the http connection on DUT connection in access point 11n mode
def test_http_otaf_ap_11n_mode(http_server, wifi_dut, wifi_access_point):
    logger().info("This test case is not listed in testrail and automated from confluence")
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host Ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
    logger().info("fetching otaf async events after upgrade....")
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing DUT....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching dut fw version after init....")
    wifi_dut.interfaces.wifi.version()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection on DUT SPI connection
def test_http_fw_upgrade_in_UART_mode_and_measure_time_C19789(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing dut....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection by enabling the power save mode in DUT
def test_http_fw_upgrade_in_ps_mode_and_measure_time_C19790(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # Enables wifi power save on DUT
    logger().info("enabling wlan power save....")
    wifi_dut.interfaces.wifi.power_save(2)

    # Enables bt power save on DUT
    logger().info("enabling bt power save....")
    wifi_dut.interfaces.wifi.bt_power_save(2)

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing dut....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "band": 0
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection on single band Q7 board
def test_http_fw_upgrade_in_Q7_board_and_measure_time_C19792(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("fetching the otaf async events after the upgrade....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing dut....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    logger().info("fetching fw version after dut init....")
    wifi_dut.interfaces.wifi.version()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default,
        "band": 2
        },
    )
# These test case verifies the firmware upgrade in DUT over the http connection on dual band A7 board
def test_http_fw_upgrade_in_A7_board_and_measure_time_C19792(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("joinig ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting ap....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)
    time.sleep(90)

    # API fetches the DUT otaf status
    logger().info("fetching otaf upgrade status....")
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(10)

    # fetches the async events generated from the DUT
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

    # API does soft reset on DUT
    logger().info("resetting dut....")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    logger().info("Initializing dut....")
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
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
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade failure in DUT over the http connection on providing the empty rps file
def test_http_fw_upgrade_failure_with_empty_rps_C19800(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("Joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting ap....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut with empty rps file....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_empty.rps")
    time.sleep(30)
    with pytest.raises(WlanError) as exc_info:

        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xBBE2, "observed wrong error code expected is 0xBBE2"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade failure in DUT over the http connection on providing the corrupted rps file
def test_http_otaf_corrupted_firmware_neg_testcase2(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut with corrupted rps....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_corrupted.rps")
    time.sleep(90)
    with pytest.raises(WlanError) as exc_info:

        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xBB41 | 0xfffd, "observed wrong error code expected is 0xBB41"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default
        },
    )
# These test case verifies the firmware upgrade failure in DUT over the http connection,when http is disabled in DUT
def test_http_fw_upgrade_failure_without_enabling_http_C19799(http_server, wifi_dut, wifi_access_point):
    # Joins the AP with given ssid and passphrase
    logger().info("joining ap....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    logger().info("starting dhcp....")
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()

    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()

    # performs the firmware upgrade on DUT over the http port
    logger().info("performing fw upgrade on dut....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
    with pytest.raises(WlanError) as exc_info:

        # API fetches the DUT otaf status
        wifi_dut.interfaces.wifi.get_http_otaf_status()
    assert exc_info.value.error_code == 0xFF74, "observed wrong error code expected is 0xff74"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
    },
)
def test_http_fw_upgrade_failure_when_enabled_only_bt_C19796(http_server, wifi_dut):
    logger().info("fetching host for server....")
    host_ip = get_host_ip()
    time.sleep(30)
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
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
    },
)
def test_http_fw_upgrade_failure_with_junk_rps_C19797(http_server, wifi_dut):
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    time.sleep(30)
    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()
    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_corrupted.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.BLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
    },
)
def test_http_fw_upgrade_failure_when_enabled_only_ble_C19796(http_server, wifi_dut):
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    time.sleep(30)
    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()
    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_removing.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
    },
)
def test_http_fw_upgrade_failure_with_non_rps_C19798(http_server, wifi_dut):
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    time.sleep(30)
    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()
    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.xml")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default
    },
)
def test_http_fw_upgrade_failure_when_enabled_only_dual_bt_C19796(http_server, wifi_dut):
    logger().info("fetching host ip for server....")
    host_ip = get_host_ip()
    time.sleep(30)
    logger().info("Fetching the DUT version...")
    wifi_dut.interfaces.wifi.version()
    with pytest.raises(WlanError) as exc_info:
        logger().info("performing fw upgrade on dut....")
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_empty.rps")
    assert exc_info.value.error_code == 0x21, "observed wrong error code expected is 0x21"