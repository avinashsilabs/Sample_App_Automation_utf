import pytest
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from interfaces.bluetooth import BLEDeviceState
from interfaces.wifi import WlanError
from utils.iperf.iperf_utils import get_host_ip
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes,RS9116AsyncEventType,RS9116TCPIPFeatureBitMap,\
    RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,RS9116ExtTCPIPFeatureBitMap
import time

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz for wlan btble.
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Execute the tests

    Author: RaviNemali
"""

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_wlan_bt_le_conn_as_master_T6179(wifi_dut,ble_client,wifi_access_point):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)
        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1)

        # Start DUT
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        # Start ble client
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        time.sleep(1)

        # Start scanning and connect to ble client
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=30)
        # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

        # Get the state of the dut
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        # Disconnect
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        # Get the state of the dut
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert not state_int == BLEDeviceState.Connected


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_wlan_bt_le_conn_as_slave_T6178(wifi_dut,ble_client,logger,wifi_access_point):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)
        # Set up DUT for BLE advertising
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[wifi_dut.interfaces.wifi.ble_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
        )

        # Not legal to start advertising if we're already advertising...
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.ble_start_advertising()
        assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

        ble_client.interfaces.bluetooth.connect(bt_dut_address)

        # Connecting will automatically stop advertising
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.ble_stop_advertising()
        assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

        ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_wlan_bt_le_conn_as_slave_T6180(wifi_dut,ble_client,logger,wifi_access_point):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)
        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1)

        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        # Start ble client
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_client_address is not None
        time.sleep(10)

        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
    logger.info(f"Scan in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_wlan_bt_le_conn_T6181(wifi_dut,ble_client,logger,wifi_access_point):
    with TimeMeasurer() as t:
        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)
        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1)

        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        # Start ble client
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_client_address is not None
        time.sleep(10)

        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
    logger.info(f"Scan in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_wlan_bt_le_conn_as_slave_T6182(wifi_dut,ble_client,logger,wifi_access_point,wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture()

        # Join Wi-Fi Access Point
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(10)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 '

        # Enables the wifi power save in dut
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode1)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode1)

        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        # Start ble client
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_client_address is not None
        time.sleep(10)

        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    logger.info(f"Scan in {t.duration} seconds")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
#This test case verifies the Http post functionality
def test_http_post_functionality_T6232(http_server, wifi_dut,http_client, wifi_access_point, logger, index_path):
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

    # API used to post the http data
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="helloravi")
    logger.info(status)
    logger.info(content)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
#This test case verifies the Https Get functionality for different lengths of url's
def test_http_get_functionality_T6231(http_server,http_client, wifi_dut, wifi_access_point, logger, index_path):

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
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
#This test case verifies the Http post functionality
def test_http_post_functionality_invalidip_T6233(http_server, wifi_dut,http_client, wifi_access_point,index_path):
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

    # API used to post the http data
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         server_ip='192.168.9.99',post_data="helloravi")
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
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default

        },
    )

# These test case verifies the firmware upgrade in DUT over the http connection in wlan mode
def test_http_otaf_T6234(http_server, wifi_dut, wifi_access_point):

    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the http port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
    time.sleep(30)

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