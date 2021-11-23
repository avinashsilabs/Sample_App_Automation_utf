import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116ConfigFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116AsyncEventType
    )
from utils.iperf.iperf_utils import get_host_ip
from interfaces.wifi import WlanError
import time
from utils.logger import get_logger


def logger():
    return get_logger(__name__)


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
# This test case verifies the http otaf for 500 iterations
def test_http_otaf_stress_overnight_testcase1(http_server, wifi_dut, wifi_access_point):
    for i in range(0,500):
        # Joins the AP with given ssid and passphrase
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Enables and assign the dhcp in DUT
        wifi_dut.interfaces.wifi.start_ip()

        # gets the server ip of host
        host_ip = get_host_ip()
        start_time = time.perf_counter_ns()
        async_timestamp = 0

        # Upgrades the firmware in DUT on http
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.rps")
        time.sleep(60)

        with pytest.raises(WlanError) as exc_info:

            # API gets the Upgrade async status
            wifi_dut.interfaces.wifi.get_http_otaf_status()
            assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD "

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

        # does the soft reset on dut
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(60)

        # initializes the dut
        wifi_dut.interfaces.wifi.init()

        # gets the dut firmware version
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
# This test case verifies the http otaf for the corrupted rps file for 500 iterations
def test_http_otaf_stress_corrupted_testcase2(http_server, wifi_dut, wifi_access_point):
    for i in range(0, 500):
        # Joins the AP with given ssid and passphrase
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Enables and assign the dhcp in DUT
        wifi_dut.interfaces.wifi.start_ip()

        # gets the server ip of host
        host_ip = get_host_ip()
        start_time = time.perf_counter_ns()
        async_timestamp = 0

        # Upgrades the firmware in DUT on http
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4_corrupted.rps")
        time.sleep(60)
        with pytest.raises(WlanError) as exc_info:

        # API gets the Upgrade async status
            wifi_dut.interfaces.wifi.get_http_otaf_status()
            assert exc_info.value.error_code == 0xFFFD, "observed wrong error code expected is 0xFFFD "
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

            # does the soft reset on dut
            wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(60)

        # initializes the dut
        wifi_dut.interfaces.wifi.init()

        # gets the dut firmware version
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
# This test case verifies the http otaf for the non rps file for 500 iterations
def test_http_otaf_stress_nonrps_testcase3(http_server, wifi_dut, wifi_access_point):
    for i in range(0, 500):
        # Joins the AP with given ssid and passphrase
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Enables and assign the dhcp in DUT
        wifi_dut.interfaces.wifi.start_ip()

        # gets the server ip of host
        host_ip = get_host_ip()
        start_time = time.perf_counter_ns()
        async_timestamp = 0

        # Upgrades the firmware in DUT on http
        wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, "/RS9116.2.5.0.4.xml")
        time.sleep(60)
        with pytest.raises(WlanError) as exc_info:

            # API gets the Upgrade async status
            wifi_dut.interfaces.wifi.get_http_otaf_status()
            assert exc_info.value.error_code == 0xbbe2, "observed wrong error code expected is 0xbbe2 "
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

        # does the soft reset on dut
        wifi_dut.interfaces.wifi.reset_soft()
        time.sleep(60)

        # initializes the dut
        wifi_dut.interfaces.wifi.init()

        # gets the dut firmware version
    wifi_dut.interfaces.wifi.version()