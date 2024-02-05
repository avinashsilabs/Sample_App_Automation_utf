import time
import pytest
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
    Si91xMqttQos
)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread
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


def get_pkt_list(wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename) -> Dict[
    str, int]:
    capture_list = []
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
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
            if layer_name in print_layers:
                if ta_address == dut_mac_address:
                    proto_layer = str(layer)
                    logger().info(f"As per sniffer capture expected packets sent by DUT..{ta_address}  ->  {proto_layer}")
                    capture_list.append(tuple([proto_layer, packet.sniff_timestamp]))
    return capture_list


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
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



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_WLAN_http_get_BLE_slave_C133481(http_server, wifi_dut, http_client, wifi_access_point, index_path,
                                                  utf_constants, wifi_sniffer, sl_collections, sniffer_filter,
                                                  ble_client):

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
    try:
        test_name = "test_Coex_sdk_WLAN_http_get_BLE_slave_C133481"
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        http_client_status = False

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
        if http_client_status:
            wifi_dut.interfaces.wifi.http_client_deinit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_http_post_BLE_slave_C133482(http_server, wifi_dut, wifi_access_point,
                                                   index_path, wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client):
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
        logger().info("stopping the HTTP server")
        http_server.interfaces.http.stop_server()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483(http_server, wifi_dut, wifi_access_point,
                                                   index_path, wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client):
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
        test_name = "test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483"
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





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_wrong_DNS_server_BLE_slave_C133480(wifi_dut, wifi_access_point,
                                                   wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client):
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
        test_name = "test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483"
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
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["dns"],
                                     test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_DNS_Query_BLE_slave_C133583(wifi_dut, wifi_access_point,
                                                   wifi_sniffer, sl_collections,
                                                   sniffer_filter, utf_constants, ble_client):
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
        test_name = "test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483"
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
        logger().info("Checking the stability for 60 secs")
        time.sleep(60)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["dns"],
                                     test_name)
        assert len(
            capture_list) > 0, "DNS packets  are not captured in the sniffer"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {
            "wifi": {"count": 2, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_tx_BLE_slave_C133477(wifi_dut, wifi_access_point,
                                                wifi_sniffer, sl_collections,
                                                sniffer_filter, utf_constants,
                                                ble_client, ssl_server):
    """
    Verify WiFi SSL Tx functionality and stability after BLE connection
    """
    try:
        test_name = "test_Coex_sdk_WLAN_SSL_tx_BLE_slave_C133477"
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
        while sw.elapsed_sec < 30:
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
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["tls"],
                                     test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info(f"Validating ssl frames")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)







@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {
            "wifi": {"count": 2, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
def test_Coex_sdk_WLAN_SSL_rx_BLE_slave_C133478(wifi_dut, wifi_access_point,
                                                wifi_sniffer, sl_collections,
                                                sniffer_filter, utf_constants,
                                                ble_client, ssl_server):
    """
    Verify WiFi SSL Rx functionality and stability after BLE connection
    """
    try:
        test_name = "test_Coex_sdk_WLAN_SSL_rx_BLE_slave_C133478"
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
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["tls"],
                                     test_name)
        assert len(
            capture_list) > 0, "SSL packets or one of the 4-way handshake packets are not captured in the sniffer"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_Coex_sdk_WLAN_MQTT_BLE_slave_C133574(wifi_dut, wifi_access_point,
                                              wifi_sniffer, sl_collections,
                                              sniffer_filter, utf_constants, ble_client,
                                              mqtt_server, mqtt_client):
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
        test_name = "test_Coex_sdk_WLAN_http_post_non_exist_ip_BLE_slave_C133483"
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

        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20)
        time.sleep(5)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"

        logger().info("Checking the stability for 60 secs")
        time.sleep(60)

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        logger().info("Stopping sniffer capture")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["mqtt"],
                                          test_name)
        assert len(
            capture_list) > 0, "MQTT packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info("sniffer validation is successful")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ble_features": Si91xBLEFeatureBitMap.Default
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )
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
        "ble_stop_scan",
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







@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
            | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ble_features": Si91xBLEFeatureBitMap.Default
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
            | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
            #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
        },
    )

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
        "ble_stop_adv",
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

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts, interface = \
            multicast_client.interfaces.multicast.multicast_params()

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

        logger().info("Starting multicast TX")

        logger().info("starting the server from Remote device")
        # starting iperf

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        host_role="S", protocol=protocol,
                                                        time_out=30, bind_address=multicast_ip)
        net_perf_client.interfaces.net_perf.start()

        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=multicast_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size="1470",
                                       ttl=30,
                                       throughput_type=2, qos=0, async_socket=1, timeout=35)

        # # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

        logger().info("Starting multicast RX")

        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip, time_out=30,
                                                        protocol=protocol, time_to_leave="32", bandwidth="60M",
                                                        host_role="C")
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=4, qos=0, async_socket=1,
                                       timeout=35)

        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        igmp_capture_list = get_pkt_list(wifi_sniffer, wifi_obj.dut_addr['dut_mac_address'], decryption_key, ["igmp"],
                                                   test_name)
        assert len(
            igmp_capture_list) > 0, "IGMP packets or one of the 4-way handshake packets are not captured in the sniffer"
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)







