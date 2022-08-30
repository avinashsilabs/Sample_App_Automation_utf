import time
from utf.utils.logger import get_logger
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116PowerSaveModes,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveProcedureTypes
)
from utf.interfaces.wifi import WlanError


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

    Author: Benazeer K

"""


def join_ip_ps_ping(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point, index_path, file_name):
    ping_count = 10
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(3)

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
    time.sleep(2)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

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

    return mac_address, bssid


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_put_functionality_c19231(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                        index_path):
    validation = True
    file_name = 'test_https_put_functionality_c19231'
    mac_address, bssid = join_ip_ps_ping(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                         index_path, file_name)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("Creating of HTTP PUT ")
    wifi_dut.interfaces.http.http_put_create()

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'unable to find the power save packet'
    time.sleep(2)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_put_func_with_post_cmd_c19233(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                             index_path):
    validation = True
    file_name = 'test_https_put_func_with_post_cmd_c19233'

    mac_address, bssid = join_ip_ps_ping(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                         index_path, file_name)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("Creating of HTTP PUT ")
    wifi_dut.interfaces.http.http_put_create()

    logger().info("Giving http post command")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                           post_data="hellothisiaatestcaseforget")
    assert exc_info.value.error_code == 0x0015, "observed wrong error code expected is 0x0015"

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'unable to find the power save packet'
    time.sleep(2)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_put_func_with_get_cmd_c19232(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                             index_path):
    validation = True
    file_name = 'test_https_put_func_with_get_cmd_c19233'

    mac_address, bssid = join_ip_ps_ping(http_server, wifi_sniffer, wifi_dut, http_client, wifi_access_point,
                                         index_path, file_name)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("Creating of HTTP PUT ")
    wifi_dut.interfaces.http.http_put_create()

    logger().info("Giving http get command")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert exc_info.value.error_code == 0x0015, "observed wrong error code expected is 0x0015"

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'unable to find the power save packet'
    time.sleep(2)
