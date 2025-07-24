import time
import pytest
import re
import itertools
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xAwsQos,
    Si91xMqttQos,
    Si91xCertificateType,
    Si91xCertIdentifier
)
from random import randrange, uniform
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread
from test_sta_ble_dle_sdk import BleThread
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
from random import randint
from utf.utils.stopwatch import Stopwatch
import uuid
from datetime import datetime
from typing import Dict
from threading import Thread
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from threading import Thread
import threading
from utf.utils import get_tls_certificate_dir

ble_obj = None

def num_sort(input_string: str):
    return list(map(int, re.findall(r'\d+', input_string)))[0]

def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. scan ,connect, data transfer
        6. ble connection slave/master
        7. check http get ,post, otaf, ssl ,dns,bgscan features 
        

    Author: Swathi.Chinthala

"""


def get_pkt_list(wifi_sniffer, dut_mac_address, wifi_access_point, decryption_key: str,
                 print_layers: list, capture_filename) -> Dict[
    str, int]:
    capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {wifi_access_point.interfaces.wifi.bssid})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    wlan_filter_file2 = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    wifi_sniffer.interfaces.capture.shell(
        f"wlantest -r {wifi_sniffer.interfaces.capture.remote_capture_file} "
        f"-p {wifi_access_point.interfaces.wifi.passphrase} "
        f"-w {wlan_filter_file2}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file2, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "wlan":
                mac_layer = str(layer)
                for count in mac_layer.split("\n"):
                    if "Transmitter address" in count:
                        ta_address = count.split(": ")[1].strip()
                        ra_address = wifi_access_point.interfaces.wifi.bssid
            if layer_name in print_layers:
                logger().info(f">>>>>>{ta_address}>>>>>>{ra_address}")
                proto_layer = str(layer)
                logger().info(f"As per sniffer capture expected packets sent by DUT & AP ..{ta_address} ... "
                              f"{ra_address}  ->  {proto_layer}")
                capture_list.append(tuple([proto_layer, packet.sniff_timestamp]))
    return capture_list


def wifi_dut_marker(ext_custom_bit=0, tcp_feat_bit=0, ext_tcp_feat_bit=0, ca_cert=None, wifi_stack_len=4096,
                    ble_stack_len=2048, client_cert=None):
    config = {

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | ext_tcp_feat_bit,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | ext_custom_bit,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": 1, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert
    return pytest.mark.config("wifi_dut", wifi=config)

@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_bgscan_BLE_slave_C133585(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        5. Join the access point and enable the dhcp
        6. Enable wlan and bt power save mode in dut after the connection
        7. Enable BG scan after wlan connection and check probe requests in sniffer
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=50,
                                                                 adv_passive_channel_time=50,
                                                                 adv_trigger_level=63,
                                                                 adv_trigger_level_change=4)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=2)

        logger().info("Initiating ping from Raspi to DUT ")
        status = ping(wifi_obj.device_ip, 60, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        ble_obj.ble_disconnect()
        wifi_obj.disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_http_get_BLE_slave_C133481(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                  utf_constants, wifi_sniffer, sl_collections, sniffer_filter,
                                                  ble_client, request):

    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    http_client_status = False
    try:
        test_name = "test_Coex_sdk_WLAN_http_get_BLE_slave_C133481"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info(f"iteration count configured in harness :{iter_count}")
        for index in range(0, iter_count):

            logger().info("\n\n***Fetching the data on http using get method***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                        server_port=80, timeout=50)
            http_client_status = True
            status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

            assert not status_dut, "failed to fetch the http data"
            assert status_client, "failed to load the http data"

            logger().info(f"content_dut: {content_dut}")
            logger().info(f"content_client: {content_client}")
            assert content_dut == content_client, "fetched data is not same as expected data"

        wifi_dut.interfaces.wifi.http_client_deinit()
        http_client_status = False

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        http_server.interfaces.http.stop_server()
        ble_client.interfaces.bluetooth.close()
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_http_post_BLE_slave_C133482(http_server, wifi_dut, wifi_access_point,
                                                   index_path, wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify the http post response
    """
    try:
        test_name = "test_Coex_sdk_WLAN_http_post_BLE_slave_C133482"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info("iteration count configured in harness :{iter_count}")
        for index in range(0, iter_count):
            logger().info(f"\n\n***Posting data using http post request for {index + 1} iteration***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                         post_data='hellotestingfrohttppostcontent')

            assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
            logger().info(status_dut)

        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        logger().info("stopping the HTTP server")
        http_server.interfaces.http.stop_server()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483(http_server, wifi_dut, wifi_access_point,
                                                   index_path, wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify the http post response with non existing ip
    """
    try:
        test_name = "test_Coex_sdk_WLAN_http_post_BLE_slave_C133482"
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info("\n\n***Posting data using http post request***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, index_path,
                                                                     post_data="hellotestingfrohttppostcontent",
                                                                     server_ip='123.123.123.123',
                                                                     expected_status=SLStatus.SL_STATUS_SI91X_CONNECT_TO_NON_EXISTING_TCP_SERVER_SOCKET,
                                                                     timeout=60)
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_wrong_DNS_server_BLE_slave_C133480(wifi_dut, wifi_access_point,
                                                   wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify dns get with wrong server
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.abcd.com",
                                                  query_timeout=120000,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED,
                                                  timeout=120)
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"], test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_Query_BLE_slave_C133583(wifi_dut, wifi_access_point,
                                                   wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify DNS get with valid server
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com",
                                                  query_timeout=120000,
                                                  timeout=120)
        logger().info(f"dns get response : {result.decode()}")
        dns_ip = (result.decode()).strip()
        logger().info("Checking the stability for 60 secs")
        wifi_dut.interfaces.wifi.ping(server_ip=dns_ip, num_ping_attempts=60,
                                           ping_timeout=10, ping_size=64)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"],
                                    test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_tx_BLE_slave_C133477(wifi_dut, wifi_access_point,
                                                wifi_sniffer, sl_collections,
                                                sniffer_filter, utf_constants,
                                                ble_client, ssl_server,
                                                request):
    """
    Verify WiFi SSL Tx functionality and stability after BLE connection
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.ble_disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["tls"], test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info(f"Validating ssl frames")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_rx_BLE_slave_C133478(wifi_dut, wifi_access_point,
                                                wifi_sniffer, sl_collections,
                                                sniffer_filter, utf_constants,
                                                ble_client, ssl_server, request):
    """
    Verify WiFi SSL Rx functionality and stability after BLE connection
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)

        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)

        sw = Stopwatch()
        while sw.elapsed_sec < 120:

            logger().info(f"sock: {sock}")
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.ble_disconnect()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["tls"],
                                    test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 )
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_MQTT_BLE_slave_C133574(wifi_dut, wifi_access_point,
                                              wifi_sniffer, sl_collections,
                                              sniffer_filter, utf_constants, ble_client,
                                              mqtt_server, mqtt_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Run MQTT srever and initiate ,subscribe,publish message from dut
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        time.sleep(5)

        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            logger().info("DUT publishes message over the topic")
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20)
            # time.sleep(10)
            msgs = []
            mq = Stopwatch()
            while mq.elapsed_sec < 20:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 1:
                    break
            assert len(msgs) >= 1, "No message is received by mqtt-client"
            assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
            assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                        "message received is wrong"

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'],
                                    wifi_access_point, decryption_key, ["mqtt"], test_name)
        assert len(
            capture_list) > 0, "MQTT packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info("sniffer validation is successful")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_Coex_sdk_fun_ble_deinit_init_wlan_data_C133566(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Ble_init, Conenct DUT as BLE master
        6. Ble deinit
        7. Repeat 5 & 6 for 5 iterations


    """
    ble_obj = None
    try:
        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        iter_count = utf_constants.get("iter_count")

        for count in range(iter_count):
            ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                ble_test_type="master",
            )
            ble_obj.start()
            ble_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.bt_stop()
            ble_client.interfaces.bluetooth.close()

        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_Coex_sdk_WLAN_multicast_TX_RX_ble_slave_C133473(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
    multicast_client
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE slave
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
        6. Run multicast TX/RX
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        logger().info(f"***** Get host IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = \
            multicast_client.interfaces.multicast.multicast_params()

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        logger().info("Starting multicast TX")
        logger().info("starting the server from Remote device")
        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        host_role="S", protocol=protocol,
                                                        time_out=120, bind_address=multicast_ip)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=multicast_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size="1470",
                                       ttl=120,
                                       throughput_type=2, qos=0, async_socket=1, timeout=150)

        # # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        net_perf_client.interfaces.net_perf.iperf_process.stop(5)
        time.sleep(5)

        def start_client():
            time.sleep(1)
            logger().info(f"***** start listening  ******")
            net_perf_client.interfaces.net_perf.start()

        logger().info("Starting multicast RX")
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=120,
                                                        protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                        host_role="C", bind_address=host_ip)
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        # net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        client_thread2 = Thread(target=start_client, args=(), )
        client_thread2.start()
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=multicast_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=120, throughput_type=4, qos=0, async_socket=1,
                                       timeout=150)
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
        net_perf_client.interfaces.net_perf.iperf_process.stop(5)
        time.sleep(5)

        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

        packet_filter = f"wlan.sa == {wifi_obj.dut_addr['dut_mac_address']} and wlan.da == {multicast_mac}  && wlan.fc.type_subtype == 0x0028"
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
            'Sniffer: Multicast packets are not captured'

        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

#
@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_Coex_sdk_WLAN_BLE_radio_ON_OFF_C133448(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz(init)
        2. sl_si91x_disable_radio
        3. sl_si91x_enable_radio
        4. rsi_bt_deinit
        5. rsi_bt_init

    """
    try:
        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            logger().info(f"iteration count: {count}")
            wifi_dut.interfaces.wifi.sl_si91x_disable_radio()
            logger().info("wlan radio off success")
            wifi_dut.interfaces.wifi.sl_si91x_enable_radio()
            logger().info("wlan radio on success")
            wifi_dut.interfaces.wifi.rsi_bt_deinit()
            logger().info("ble deinit success")
            wifi_dut.interfaces.wifi.ble_start(skip_bt_local_address=True)
            logger().info("ble init success")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_ble_bd_addr_wlan_TCP_TX_C133564(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    ble_obj = None
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Run TCP-TX
        6. query for local bd address
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            net_perf_client=net_perf_client,
            protocol=protocol,
            timeout=200,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.bt_get_local_address()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker()
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_Disconnect_BLE_while_WLAN_TCP_RX_C133559(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    ble_obj = None
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Wlan Scan ,connect ,ip ,powersave,ping
        3. Advertise remote BLE device
        4. Scan and connect  from DUT to remote BLE device
        5. Run TCP RX
        6. Disconnect BLE while TCP RX is running
        7. repeat 3 ,4, 6 for 5 times
    """
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        iter_count = utf_constants.get("iter_count")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            bond_info=1
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="RX",
            timeout=iter_count*100
        )
        wifi_obj.join_to_ap()

        for count in range(iter_count):
            ble_obj.start()
            ble_obj.wait_for_exit()
            if count == 0:
                wifi_obj.start()
            logger().info("checking BLE connection stability for 60 seconds")
            time.sleep(60)
            ble_obj.ble_disconnect(disconnect_from="dut")
            ble_client.interfaces.bluetooth.close()
        wifi_obj.wait_for_exit()

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient,
                 ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "load_default_fw",
        "disassociated",
    ],
)
def test_Coex_sdk_otaf_ble_slave_C133484(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    http_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. BLE connection as slave
        3. Join the access point and enable the dhcp
        4. Upgrade firmware through otaf.
        5. Query firmware version
        6. AT the end load default fw


    """
    ble_obj = None
    ble_init = False
    try:
        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )
        ble_init = True
        http_url = UtfConfig.instance().defaults["wifi"].get("http_url", None)
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(http_url) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(http_url), write_content=http_url)
        ble_obj.start()
        ble_obj.wait_for_exit()

        fw_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        logger().info("fetching server ip....")
        host_ip = http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"server ip is {host_ip}")
        start_time = time.time()
        logger().info(f" start firmware upgrade: {start_time}")
        logger().info("performing firmware upgrade....")
        wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip, host_name=host_ip, url_address=address1,
                                                  timeout=200, async_timeout=300)
        wifi_dut.interfaces.wifi.memory_free(address1)
        finish_time = time.time()
        logger().info(f"firmware upgraded : {finish_time}")
        time_duration = (finish_time - start_time)
        logger().info(f"Time taken to upgrade firmware is: {time_duration}")

        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
        logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
        wifi_dut.interfaces.wifi.reset()
        ble_init = False
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_after_upgrade}")
        assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                      f" firmware through otaf"

        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_mac_address,
            wifi_obj.ap_mac_address,
            sniffer_filter,
            power_save=False,
        )
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_init:
            if ble_obj is not None:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)






@wifi_dut_marker()
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_BLE_RSSI_WLAN_HTTP_download_C133563(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        ble_client,
        request,
        utf_constants,
        sl_collections,
        wifi_client,
        sniffer_filter,
        http_server,
        index_path
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Start http file download with 10MB file size
        6. Connect DUT as BLE master
        7. Query RSSI when http_download in progress
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            http_server=http_server,
            index_path=index_path
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.get_ble_rssi_value(ble_obj.ble_client_address)
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_static_dns_server_BLE_slave_C133479(wifi_dut, wifi_access_point,
                                                   wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify DNS get with valid server
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        logger().info(
            "=======DNS address command is given when only primary DNS server ip address is given statically ========")
        wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                      secondary_dns_server_address="NULL")
        dns_ip = wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=120000,
                                                  ip_version="ipv4", timeout=120)

        logger().info("Checking the stability for 60 secs")
        wifi_dut.interfaces.wifi.ping(server_ip=dns_ip, num_ping_attempts=10,
                                           ping_timeout=10, ping_size=64)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"], test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_mac_based_conn_BLE_slave_C133485(wifi_dut, wifi_access_point,
                                                        wifi_sniffer, sl_collections,
                                                        sniffer_filter, utf_constants,
                                                        ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point by using mac and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection

    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            bond_info=1
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            mac=wifi_access_point.interfaces.wifi.bssid
        )
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            ble_obj.start()
            ble_obj.wait_for_exit()
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()
            ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient,
                 ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "load_default_fw",
        "disassociated",
    ],
)
def test_Coex_sdk_http_otaf_ble_scan_C551661(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    http_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. BLE connection as slave
        3. Join the access point and enable the dhcp
        4. Upgrade firmware through otaf.
        5. Query firmware version
        6. AT the end load default fw


    """
    ble_init = False
    try:
        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")


        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        ble_init = True
        http_url = UtfConfig.instance().defaults["wifi"].get("http_url", None)
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(http_url) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(http_url), write_content=http_url)
        ble_obj.start()
        ble_obj.wait_for_exit()

        fw_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        logger().info("fetching server ip....")
        host_ip = http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"server ip is {host_ip}")
        start_time = time.time()
        logger().info(f" start firmware upgrade: {start_time}")
        logger().info("performing firmware upgrade....")

        wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip, host_name=host_ip, url_address=address1,
                                                  timeout=200, async_timeout=300)
        wifi_dut.interfaces.wifi.memory_free(address1)
        finish_time = time.time()
        logger().info(f"firmware upgraded : {finish_time}")
        time_duration = (finish_time - start_time)
        logger().info(f"Time taken to upgrade firmware is: {time_duration}")

        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
        logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
        wifi_dut.interfaces.wifi.reset()
        ble_init = False
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_after_upgrade}")
        assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                      f" firmware through otaf"

        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_mac_address,
            wifi_obj.ap_mac_address,
            sniffer_filter,
            power_save=False,
        )
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_init:
            if ble_obj is not None:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "load_default_fw",
        "disassociated",
        "clear_certs",
    ],
)
def test_Coex_sdk_https_otaf_ble_slave_C551662(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    http_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. BLE connection as slave
        3. Join the access point and enable the dhcp
        4. Upgrade firmware through otaf.
        5. Query firmware version
        6. AT the end load default fw


    """
    ble_obj = None
    ble_init = False
    try:
        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")
        http_url = UtfConfig.instance().defaults["wifi"].get("http_url", None)
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(http_url) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(http_url), write_content=http_url)
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)
        index = 1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=300,
            periodic_delay=1,
            ble_pairing=1,
            address=address2,
            conn_interval=45,
            gatt=True
        )
        ble_init = True

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        fw_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        ble_obj.ble_connect(role="slave")
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.service_discovery_on_remote()
        ble_obj.start()
        time.sleep(5)
        logger().info("fetching server ip....")
        host_ip = http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"server ip is {host_ip}")
        start_time = time.time()
        logger().info(f" start firmware upgrade: {start_time}")
        logger().info("performing firmware upgrade....")
        wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, host_name=host_ip,
                                                  url_address=address1, port=443, timeout=200, async_timeout=300)
        wifi_dut.interfaces.wifi.memory_free(address1)
        finish_time = time.time()
        logger().info(f"firmware upgraded : {finish_time}")
        time_duration = (finish_time - start_time)
        logger().info(f"Time taken to upgrade firmware is: {time_duration}")
        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")
        logger().info(f"\n ***firmware versions not matched after loading firmware through otaf \n")
        try:
            ble_obj.wait_for_exit()
        except Exception as e:
            logger().error(f"Exception occurred: {e}")
        wifi_dut.interfaces.wifi.reset()
        ble_init = False
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_after_upgrade = wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(f"\n\n ***firmware versions before otaf:{fw_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_after_upgrade}")
        assert fw_before_upgrade != fw_after_upgrade, f"firmware versions should not match after loading" \
                                                      f" firmware through otaf"

        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(
            wifi_access_point,
            wifi_sniffer,
            wifi_obj.dut_mac_address,
            wifi_obj.ap_mac_address,
            sniffer_filter,
            power_save=False,
        )
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                               | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(3)
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD
                              | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
                ca_cert=[("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    # ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
                 )
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "clear_certs"])
def test_coex_sdk_SSL_AWS_ble_slave_C133575(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1, cert2,
                                  sl_collections, sniffer_filter, utf_constants, request, wifi_client, ble_client):
    """
    Connection with three SSL Sockets, two local OpenSSL Servers and One AWS Cloud Server
    """
    try:
        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                     Si91xCertificateType.SL_NET_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2)
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                     Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2)

        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        # port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
        )

        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(2):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            if sock_count == 0:
                socket_port = port1
            # elif sock_count == 1:
            #     socket_port = port2
            else:
                socket_port = port3
                result = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
                server_ip = result.strip().decode()
                logger().info(f"aws_server_ip {server_ip}")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        pkt_count = 1000
        for count in range(5):
            for socket in range(1, 2):
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=20)
            socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                              number_of_pkts=pkt_count,
                                                                              time_interval=500)
            sock_count = 0
            bytes_sent_list = []
            for socket_stats in socket_list:
                logger().info(
                    f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
                bytes_sent_list.append(socket_stats[0])
                sock_count = sock_count + 1
            for socket in range(1, 2):
                if ssl_server.interfaces.ssl.socket_connection_status(socket):
                    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                    assert bytes_sent_list[socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the" \
                                                                          f"remote peer not matched on socket {socket}"
        for sock in range(2):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger().info(f"Successfully closed socket_id '{sock}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL
                                | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                                | Si91xTCPIPFeatureBitMap.DNSClient
                                | Si91xTCPIPFeatureBitMap.Ping,
                client_cert=["silabs_dgcert_ca.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.firmware_app("test_azure")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "azure_iot_unsubscribe", "azure_iot_disconnect",
                             "disassociated"])
def test_azure_mqtt_subscribe_publish_ble_adv_scan_C133584(firmware_loader, wifi_access_point, wifi_dut, wifi_sniffer, azure_iot_client,
                                             sl_collections, wifi_client, request, utf_constants, sniffer_filter,
                                             ble_client):

    """
    Test Description:
    This test case verifies the Azure MQTT subscribe and publish functionality.
    """
    try:

        test_name = request.node.name
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {power_save}")
        connection_string = azure_iot_client.interfaces.device.config["connection_string_device"]
        [(host_name, device, shared_key)] = re.findall(
            r'HostName=(.*);DeviceId=(.*);SharedAccessKey=(.*)',
            connection_string)
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                   cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.
                                                   SL_NET_TLS_CLIENT_CREDENTIAL_START)
        wifi_dut.interfaces.wifi.clear_certificate(cert_index=0,
                                                   cert_type=Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                   cert_identifier=Si91xCertIdentifier.
                                                   SL_NET_TLS_CLIENT_CREDENTIAL_START)
        # self.wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("connecting to access point.....")
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()
        result = wifi_dut.interfaces.wifi.dns_get(domain_name=host_name,
                                                  query_timeout=20000,
                                                  timeout=100)
        host_ip = (result.decode()).strip()
        sock_id = wifi_dut.interfaces.wifi.socket("AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock_id, "SOL_TCP", "TCP_ULP", "tls")
        wifi_dut.interfaces.wifi.bsdSetSocketOption(socket_fd=sock_id, option_level='SOL_SOCKET',
                                                    option_name='SO_RCVTIMEO')
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock_id, host_ip, 4, 8883)  # "40.78.196.98")

        wifi_dut.interfaces.wifi.azure_iot_init(
            hostname=host_name,
            device_id="symmetric_device",
            port=4002,
            mode=0,
            symmetrickey=shared_key,
            timeout=60)

        message = text_generator(size=10)
        logger().info(f"Message is:{message}")
        count = 0
        wifi_dut.interfaces.wifi.azure_iot_subscribe(timeout=60)
        sw = Stopwatch()

        logger().info(f"Message is:{message}")
        azure_iot_client.interfaces.hub.received_messages.clear()

        with azure_iot_client.interfaces.hub.start_receiving_events(duration=10):
            while sw.elapsed_sec < 60:
                wifi_dut.interfaces.wifi.azure_iot_publish(payload=message, maxcount=1, timeout=60)
                count = count + 1
                # time.sleep(5)
        assert message in azure_iot_client.interfaces.hub.received_messages, \
            "message sent from device not received on cloud"
        logger().info(f"message sent from device received on cloud {message}")
        received_msgs = azure_iot_client.interfaces.hub.received_messages

        assert received_msgs.count(message) == count, \
            "Number of times message sent from device not received on cloud"
        logger().info(f"Number of times message sent from device {count} received on cloud"
                      f" {received_msgs.count(message)}")
        ble_client.interfaces.bluetooth.close()
        ble_client_address = sl_collections.scan_from_remote_device(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
        )
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.azure_iot_unsubscribe()
        wifi_dut.interfaces.wifi.azure_iot_disconnect()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        azure_iot_client.interfaces.device.disconnect()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        azure_iot_client.interfaces.device.disconnect()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_http_get_BLE_slave_CI_30ms_C783412(http_server, wifi_dut, http_client, wifi_access_point,
                                                          index_path,
                                                          utf_constants, wifi_sniffer, sl_collections, sniffer_filter,
                                                          ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    http_client_status = False
    ble_obj = None
    try:
        test_name = "test_Coex_sdk_WLAN_http_get_BLE_slave_C783412"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=30
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info(f"iteration count configured in harness :{iter_count}")
        for index in range(0, iter_count):
            logger().info("\n\n***Fetching the data on http using get method***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                        server_port=80, timeout=50)
            http_client_status = True
            status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http,
                                                                                 index_path)

            assert not status_dut, "failed to fetch the http data"
            assert status_client, "failed to load the http data"

            logger().info(f"content_dut: {content_dut}")
            logger().info(f"content_client: {content_client}")
            assert content_dut == content_client, "fetched data is not same as expected data"

        wifi_dut.interfaces.wifi.http_client_deinit()
        http_client_status = False

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        http_server.interfaces.http.stop_server()
        ble_client.interfaces.bluetooth.close()
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_http_get_BLE_slave_CI_80ms_C783413(http_server, wifi_dut, http_client, wifi_access_point,
                                                          index_path,
                                                          utf_constants, wifi_sniffer, sl_collections, sniffer_filter,
                                                          ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    http_client_status = False
    ble_obj = None
    try:
        test_name = "test_Coex_sdk_WLAN_http_get_BLE_slave_C783413"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=80
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info(f"iteration count configured in harness :{iter_count}")
        for index in range(0, iter_count):
            logger().info("\n\n***Fetching the data on http using get method***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                        server_port=80, timeout=50)
            http_client_status = True
            status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http,
                                                                                 index_path)

            assert not status_dut, "failed to fetch the http data"
            assert status_client, "failed to load the http data"

            logger().info(f"content_dut: {content_dut}")
            logger().info(f"content_client: {content_client}")
            assert content_dut == content_client, "fetched data is not same as expected data"

        wifi_dut.interfaces.wifi.http_client_deinit()
        http_client_status = False

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        http_server.interfaces.http.stop_server()
        ble_client.interfaces.bluetooth.close()
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
def test_Coex_sdk_WLAN_http_get_BLE_slave_CI_150ms_C783414(http_server, wifi_dut, http_client, wifi_access_point,
                                                           index_path,
                                                           utf_constants, wifi_sniffer, sl_collections, sniffer_filter,
                                                           ble_client, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http get for http content
        5. Verify the http get response
    """
    http_client_status = False
    ble_obj = None
    try:
        test_name = "test_Coex_sdk_WLAN_http_get_BLE_slave_C783414"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=150
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init()

        logger().info(f"iteration count configured in harness :{iter_count}")
        for index in range(0, iter_count):
            logger().info("\n\n***Fetching the data on http using get method***\n\n")
            status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                        server_port=80, timeout=50)
            http_client_status = True
            status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http,
                                                                                 index_path)

            assert not status_dut, "failed to fetch the http data"
            assert status_client, "failed to load the http data"

            logger().info(f"content_dut: {content_dut}")
            logger().info(f"content_client: {content_client}")
            assert content_dut == content_client, "fetched data is not same as expected data"

        wifi_dut.interfaces.wifi.http_client_deinit()
        http_client_status = False

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        http_server.interfaces.http.stop_server()
        ble_client.interfaces.bluetooth.close()
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_wrong_DNS_server_BLE_slave_CI_30ms_C783409(wifi_dut, wifi_access_point,
                                                                      wifi_sniffer, sl_collections,
                                                                      sniffer_filter, utf_constants, ble_client,
                                                                      request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify dns get with wrong server
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=30
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.abcd.com",
                                                  query_timeout=120000,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED,
                                                  timeout=120)
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"], test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_wrong_DNS_server_BLE_slave_CI_80ms_C783410(wifi_dut, wifi_access_point,
                                                                      wifi_sniffer, sl_collections,
                                                                      sniffer_filter, utf_constants, ble_client,
                                                                      request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify dns get with wrong server
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=80
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.abcd.com",
                                                  query_timeout=120000,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED,
                                                  timeout=120)
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"], test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.DNSClient)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_wrong_DNS_server_BLE_slave_CI_150ms_C783411(wifi_dut, wifi_access_point,
                                                                       wifi_sniffer, sl_collections,
                                                                       sniffer_filter, utf_constants, ble_client,
                                                                       request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Advertise BLE DUT
        3. Scan from remote BLE device and connect to DUT
        4. Scan and Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Verify dns get with wrong server
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=150
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()

        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.abcd.com",
                                                  query_timeout=120000,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED,
                                                  timeout=120)
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["dns"], test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_tx_BLE_slave_CI_30ms_C783415(wifi_dut, wifi_access_point,
                                                        wifi_sniffer, sl_collections,
                                                        sniffer_filter, utf_constants,
                                                        ble_client, ssl_server,
                                                        request):
    """
    Verify WiFi SSL Tx functionality and stability after BLE connection
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=30
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.ble_disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["tls"], test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info(f"Validating ssl frames")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_tx_BLE_slave_CI_80ms_C783416(wifi_dut, wifi_access_point,
                                                        wifi_sniffer, sl_collections,
                                                        sniffer_filter, utf_constants,
                                                        ble_client, ssl_server,
                                                        request):
    """
    Verify WiFi SSL Tx functionality and stability after BLE connection
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=80
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.ble_disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["tls"], test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info(f"Validating ssl frames")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_tx_BLE_slave_CI_150ms_C783417(wifi_dut, wifi_access_point,
                                                         wifi_sniffer, sl_collections,
                                                         sniffer_filter, utf_constants,
                                                         ble_client, ssl_server,
                                                         request):
    """
    Verify WiFi SSL Tx functionality and stability after BLE connection
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=150
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        wifi_obj.join_to_ap()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.ble_disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], wifi_access_point,
                                    decryption_key, ["tls"], test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info(f"Validating ssl frames")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


