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
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import WlanError


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def join_get_ip(wifi_dut, wifi_access_point, ping_count):
    logger().info("Initiating scan in dut")
    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    for count in range(3):
        try:
            logger().info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            break
        except:
            logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count + 1}")
            time.sleep(1)

    device_ip = None
    for count in range(3):
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
            time.sleep(1)

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
    return device_ip


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

    Author: Ravi Nemali & Benazeer K

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
@pytest.mark.parametrize("index_path", {"index_long_lf.html", "index_long_crlf.html", "6KB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_with_different_lengths_C19213(http_server, http_client, wifi_dut, wifi_access_point, index_path,
                                                utf_constants, wifi_sniffer):
    ping_count = utf_constants.get("ping_count")

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19213')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info(f"fetching the data from server bt get method for {index_path}")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert status, "failed to fetch the http data"
    assert content, "failed to load the http data"

    logger().info(status)
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_get_with_invalid_IP_C19212(http_server, wifi_dut, wifi_access_point, index_path, utf_constants,
                                         wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19212')
    time.sleep(3)

    ping_count = utf_constants.get("ping_count")
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the data from  http server using get method")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, server_ip='192.168.9.99')

    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_get_with_100_mb_file_C19214(http_server, wifi_dut, wifi_access_point, index_path, utf_constants,
                                          wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19214')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    logger().info(f"path{index_path}")

    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetching the http data using get method")
    result = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert result, "fetched data is empty,failed to get data"

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_get_functionality_comparison_C19215(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                  utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19215')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")

    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("fetches the http data using get method")
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger().info(status)
    logger().info(content)
    assert content == content1, "received data is not same as expected data"
    time.sleep(30)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_post_functionality_C19219(http_server, wifi_dut, http_client, wifi_access_point, utf_constants,
                                        wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19219')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellothisiaatestcaseforget")
    assert status, "failed to get http data"
    assert content, "failed to get http data"
    logger().info(status)
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_post_functionality_for_50mb_data_C19222(http_server, wifi_dut, http_client, wifi_access_point,
                                                      utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19222')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellohvbsjvhkjsdhvhksdhvksjdvravvjvdhi"
                                                                   "jhdvbjhbjdhjvjdbjbsdwfbkjdhkdhfkk"
                                                                   "jhdvjdjhddjhjgfjhjfdkhfhhfkhjhkfhjkfhkhfhak")
    assert status, "failed to get http data"
    logger().info(status)
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py", "index_long_crlf.html", "6KB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_different_urls_C19224(http_server, wifi_dut, http_client, wifi_access_point,
                                                       index_path, utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19224')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info(f"http functionality using post method {index_path}")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                         post_data="hellothisisfordifferenturlsusedtopostthed"
                                                                   "atoverthehttppostprotocol")
    assert status, "failed to post data to http server"
    logger().info(status)
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_post_functionality_for_5_iterations_C19221(http_server, wifi_dut, http_client, wifi_access_point,
                                                         utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19221')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        join_get_ip(wifi_dut, wifi_access_point, ping_count)
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

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_http_post_functionality_invalid_ip_C19220(http_server, wifi_dut, http_client, wifi_access_point,
                                                   utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19220')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                           server_ip='192.168.9.99',
                                           post_data="hellothisisatestcase")
    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_http_get_func_host_name_with_tcp_C19218(http_server, wifi_dut, http_client, net_perf_client, wifi_access_point,
                                                 wifi_client, protocol, utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19216')
    time.sleep(3)
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        device_ip = join_get_ip(wifi_dut, wifi_access_point, ping_count)
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        logger().info("sends data to http server using post method")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellotestingfrohttppostcontent")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)  # < 0.1, "fail to ping host"
        logger().info("ping successful to host")

        time.sleep(2)
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(5)

        logger().info(f"Host IP: {host_ip}")
        logger().info(f"Dut IP: {device_ip}")
        logger().info(f"Protocol: {protocol}")

        print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** open socket and send traffic  ******")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)

        assert status, "failed to post data"
        logger().info(status)

        logger().info("disconnecting ap")
        wifi_dut.interfaces.wifi.leave()
    logger().info(content)
    logger().info(f"******************* iteration {count} completed ********************* ")

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
def test_https_get_with_wrong_certificate_C19211(http_server, wifi_sniffer, http_client, wifi_dut,
                                                 wifi_access_point, index_path):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_get_with_wrong_certificate_C19211')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

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
def test_https_post_functionality_for_5_iterations_C19225(http_server, wifi_dut, http_client, wifi_access_point,
                                                          utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19225')
    time.sleep(3)
    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        join_get_ip(wifi_dut, wifi_access_point, ping_count)
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

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_http_get_func_host_name_with_udp_C19218(http_server, wifi_dut, http_client, net_perf_client, wifi_access_point,
                                                 wifi_client, protocol, utf_constants, wifi_sniffer):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19216')
    time.sleep(3)
    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")
    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        device_ip = join_get_ip(wifi_dut, wifi_access_point, ping_count)
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        logger().info("sends data to http server using post method")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellotestingfrohttppostcontent")
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)  # < 0.1, "fail to ping host"
        logger().info("ping successful to host")

        time.sleep(2)
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        time.sleep(5)

        logger().info(f"Host IP: {host_ip}")
        logger().info(f"Dut IP: {device_ip}")
        logger().info(f"Protocol: {protocol}")

        print('\n\n ********** Calling IPERF TX, TCP traffic for all Qos services ********************\n\n')

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()

        logger().info(f"***** open socket and send traffic  ******")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughtput..."
        __print_throughput(tp)
        time.sleep(5)

        assert status, "failed to post data"
        logger().info(status)

        logger().info("disconnecting ap")
        wifi_dut.interfaces.wifi.leave()
    logger().info(content)
    logger().info(f"******************* iteration {count} completed ********************* ")

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=10)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_port10_C19227_case1(wifi_sniffer, http_server, wifi_dut, http_client,
                                                      wifi_access_point):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_port10_C19227_case1')
    time.sleep(3)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info("sends data to http server using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellotestingfrohttppostcontent")
    assert status, "failed to post data"
    logger().info(status)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("disconnecting ap")
    wifi_dut.interfaces.wifi.leave()
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=200)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_port200_C19227_case2(wifi_sniffer, http_server, wifi_dut, http_client,
                                                       wifi_access_point):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_port10_C19227_case2')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info("sends data to http server using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellotestingfrohttppostcontent")
    assert status, "failed to post data"
    logger().info(status)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("disconnecting ap")
    wifi_dut.interfaces.wifi.leave()
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=2000)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_port2000_C19227_case3(wifi_sniffer, http_server, wifi_dut, http_client,
                                                        wifi_access_point):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_port2000_C19227_case3')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info("sends data to http server using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellotestingfrohttppostcontent")
    assert status, "failed to post data"
    logger().info(status)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("disconnecting ap")
    wifi_dut.interfaces.wifi.leave()
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=20000)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_port20000_C19227_case4(wifi_sniffer, http_server, wifi_dut, http_client,
                                                         wifi_access_point):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_port20000_C19227_case4')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info("sends data to http server using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellotestingfrohttppostcontent")
    assert status, "failed to post data"
    logger().info(status)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("disconnecting ap")
    wifi_dut.interfaces.wifi.leave()
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config("http_server", port=443)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_port443_C19227_case5(wifi_sniffer, http_server, wifi_dut, http_client,
                                                       wifi_access_point):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_port443_C19227_case5')
    time.sleep(3)

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    logger().info("sends data to http server using post method")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellotestingfrohttppostcontent")
    assert status, "failed to post data"
    logger().info(status)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    logger().info("disconnecting ap")
    wifi_dut.interfaces.wifi.leave()
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    }
)


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_get_func_with_extend_header_C19217(wifi_sniffer, http_server, wifi_dut, http_client, wifi_access_point,
                                                 index_path):
    validation = True
    ping_count1 = 120
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_http_get_func_with_extend_header_C19217')
    time.sleep(2)

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    join_get_ip(wifi_dut, wifi_access_point, ping_count1)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info("API used to post the http data")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                         post_data="hellothisiaatestcaseforget")
    assert status, "failed to get http data"
    assert content, "failed to get http data"
    logger().info(status)
    logger().info(content)

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    packet_filter3 = f'wlan.addr == {mac_address} && http'

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3), ['packet_count']


pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
    }
)


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_func_with_http_abort_C19228(wifi_sniffer, http_server, wifi_dut, http_client, wifi_access_point,
                                               index_path, utf_constants):
    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_http_post_func_with_http_abort_C19228')
    time.sleep(2)

    for count in range(0, iter_count):
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {bssid}")

        join_get_ip(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

        logger().info("API used to post the http data")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellothisiaatestcaseforget")
        logger().info("waiting for 30s")
        time.sleep(30)
        logger().info("API used to abort the http connection")
        wifi_dut.interfaces.wifi.http_abort()

        assert status, "failed to get http data"
        assert content, "failed to get http data"
        logger().info(status)
        logger().info(content)

        packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                         f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

        logger().info(f"DUT going to leave")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(3)
        logger().info(f"******************* iteration {count} completed ********************* ")

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
def test_http_server_closes_conn_before_C19230(http_server, wifi_dut, wifi_sniffer, http_client,
                                               wifi_access_point, utf_constants):
    iter_count = utf_constants.get("iter_count")
    ping_count = utf_constants.get("ping_count")
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_http_server_closes_conn_before_C19230')
    time.sleep(2)

    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'

    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    for count in range(0, iter_count):
        logger().info("API used to post the http data")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellothisiaatestcaseforget")
        assert status, "failed to get http data"
        assert content, "failed to get http data"
        logger().info(status)
        logger().info(content)

    logger().info(f"DUT going to leave")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(3)

    logger().info("Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']


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
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py", "index_long_crlf.html", "index.html", "6KB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_post_functionality_different_urls_C19226(http_server, wifi_dut, http_client, wifi_access_point,
                                                        index_path, utf_constants, wifi_sniffer):
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_https_post_functionality_different_urls_C19226')
    time.sleep(3)
    ping_count = 120
    join_get_ip(wifi_dut, wifi_access_point, ping_count)
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {bssid}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    packet_filter1 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && ' \
                     f'(wlan.sa == {mac_address}) && (wlan.da == {bssid}))'
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    logger().info(f"http functionality using post method {index_path}")
    status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                         post_data="hellothisisfordifferenturlsusedtopostthed"
                                                                   "atoverthehttppostprotocol")
    assert status, "failed to post data to http server"
    logger().info(status)
    logger().info(content)

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Sniffer validation for power save packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ['packet_count']
