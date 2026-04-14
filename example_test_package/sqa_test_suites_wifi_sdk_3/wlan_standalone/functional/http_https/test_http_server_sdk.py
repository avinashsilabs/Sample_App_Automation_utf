import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
)
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
import string
import random
import re
from utf.utils.thread_base import ThreadBase
from datetime import datetime

"""The testcases added in this file can run below test steps :
        1. Configuration of DUT
        2. Association of Third party AP's
        3. Get the valid IP address
        4. HTTP get request from the Raspberry-pi to DUT 

setup requirement:
        1. Soc Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer 

Author : Saurabh Sharma

"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker(ca_cert=None, client_cert=None, client_key=None,):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert

    if client_key:
        config["client_key"] = client_key
    return pytest.mark.config("wifi_dut", wifi=config)

class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, http_server=None
                 , http_client=None, sl_collections=None, sniffer_filter=None, utf_constants=None, index_path=None,
                 test_case=None, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.http_server = http_server
        self.http_client = http_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.utf_constants = utf_constants
        self.index_path = index_path
        self.test_case = test_case
        self.keep_alive_time = None
        self.dut_addr = None
        self.wifi_client = wifi_client

    def run(self):
        try:

            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.
                                                                     channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

            self.dut_addr = self.sl_collections.join_to_wifi_network(
                self.wifi_dut, self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated)

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
            raise e

    def http_functionality(self):
        method = "GET"
        current_time = time.time()

        if self.test_case == '19235' or self.test_case == '528822' or self.test_case == '641388' or self.test_case == '708786':
            self.wifi_dut.interfaces.wifi.http_server_init()

        if self.test_case == '564051':
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            self.wifi_dut.interfaces.wifi.http_server_init(send_large_data=1, data=data)

        self.wifi_dut.interfaces.wifi.http_server_start()

        i = 0
        if self.test_case == '708786':
            sw = Stopwatch()
            while sw.elapsed_sec < 120:
                logger().info(f"...... sending http get request from third party client to DUT .......")
                i = i + 1
                status, resp_content = self.http_client.interfaces.http.http_request(
                    self.http_server.interfaces.http, method, self.index_path, server_ip=self.dut_addr['device_ip'],
                    timeout=20)

                logger().info(f"........ length of DUT webpage {len(resp_content)}\n\n .......")
                logger().info(f"........ contents of webpage {resp_content}\n\n\n ........")

                file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
                webpage = "./reports/" + self.capture_filename + "webpage" + file_time_stamp + ".html"

                logger().info(f"........ webpage ID sent by DUT is {webpage} ..........")
                with open(webpage, "w") as recv:
                    recv.write(resp_content.decode())
                logger().info(f"webpage refreshment done {i}")
                time.sleep(5)
        else:
            logger().info(f"...... sending http get request from third party client to DUT .......")

            status, resp_content = self.http_client.interfaces.http.http_request(
                self.http_server.interfaces.http, method, self.index_path, server_ip=self.dut_addr['device_ip'],
                timeout=20)

            logger().info(f"........ length of DUT webpage {len(resp_content)}\n\n .......")
            logger().info(f"........ contents of webpage {resp_content}\n\n\n ........")

            file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
            webpage = "./reports/" + self.capture_filename + "webpage" + file_time_stamp + ".html"

            logger().info(f"........ webpage ID sent by DUT is {webpage} ..........")
            with open(webpage, "w") as recv:
                recv.write(resp_content.decode())

        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()
        time.sleep(2)

        if self.test_case == '19235' or self.test_case == '528822' or self.test_case == '564051':
            self.wifi_dut.interfaces.wifi.leave()

    def _curl_request(self, cmd, method, file_time_stamp):
        logger().info(f"Running: {cmd}")
        result = self.wifi_client.interfaces.wifi.shell.execute(cmd)
        returncode = result[0]
        response = result[1].decode(errors="ignore")
        if returncode != 0:
            logger().info(f"\n........Print RESPONSE {response} .......\n")
            raise RuntimeError(f"curl failed with return code {returncode}")
        if "Not Found" in response:
            raise Exception(f"\n Received 404 Not Found during {method} request, skipping further requests.\n")
        logger().info(f"\n\n ........#length of DUT webpage {len(response)} ....... \n\n")
        logger().info(f"\n\n ........ contents of webpage {response} ........\n\n")
        with open(f"./reports/{self.capture_filename}_{method}_webpage{file_time_stamp}.html", "w") as f:
            f.write(response)

    def http_curl_functionality(self):
        current_time = time.time()
        self.wifi_dut.interfaces.wifi.http_server_init()
        self.wifi_dut.interfaces.wifi.http_server_start()
        dut_ip = self.dut_addr['device_ip']
        path = self.index_path
        file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        # HTTP GET
        get_cmd = f"curl -v http://{dut_ip}{path}"
        self._curl_request(get_cmd, "GET", file_time_stamp)
        # HTTP PUT (file upload)
        put_cmd = f"curl -v -X PUT --data-binary @{path} http://{dut_ip}{path}"
        self._curl_request(put_cmd, "PUT", file_time_stamp)
        # HTTP POST (file upload)
        post_cmd = f"curl -v -X POST --data-binary @{path} http://{dut_ip}{path}"
        self._curl_request(post_cmd, "POST", file_time_stamp)
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()
        time.sleep(2)


@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19235')
def test_wifi_sdk_query_webpage_http_server_c19235(
        wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, request, sniffer_filter, sl_collections,
        utf_constants):
    """Verify module functionality when remote peer query for webpage from HTTP server for multiple times"""
    try:
        capture_filename = request.node.name
        index_path = "/test"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='19235', index_path=index_path)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            wifi_obj.http_functionality()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e

@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C528822')
def test_wifi_sdk_query_webpage_http_server_c528822(
        wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, request, sniffer_filter, sl_collections,
        utf_constants):

    """Verify http webpage at client side using http server functionality"""
    try:
        capture_filename = request.node.name
        index_path = "/data"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='528822', index_path=index_path)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            wifi_obj.http_functionality()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e

@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C564051')
def test_wifi_sdk_webpage_http_server_write_data_c564051(
        wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, request, sniffer_filter, sl_collections,
        utf_constants):

    """Verify http webpage at client side using http_server_write_data API"""
    try:
        capture_filename = request.node.name
        index_path = "/cert1.pem"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='564051', index_path=index_path)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            wifi_obj.http_functionality()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e

@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C641388')
def test_wifi_sdk_query_webpage_http_server_c641388(
        wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, request, sniffer_filter, sl_collections,
        utf_constants):
    """Verify http webpage at client side using http server functionality in loop
    (http server init--start-open DUTIP/test--deinit ) without wlan disconnect"""
    try:
        capture_filename = request.node.name
        index_path = "/test"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='641388', index_path=index_path)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.http_functionality()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e

@pytest.mark.config(
    "wifi_dut",
       wifi = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "boot_option": 49,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["clear_certs"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "password": "12345678"}
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C641377')
def test_Verify_http_server_with_GET_PUT_POST_using_3rd_party_curl_client_C641377(wifi_dut, wifi_client,
                                                                                  wifi_sniffer, wifi_access_point,
                                                                                  request, http_client,
                                                                                  sniffer_filter, utf_constants,
                                                                                  sl_collections):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Scan and Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate http server functionality with our DUT HTTP GET, PUT, POST using 3rd party curl client
    """
    try:
        capture_filename = request.node.name
        index_path = "/test"
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.
                                                            channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='641377', index_path=index_path, wifi_client=wifi_client)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.http_curl_functionality()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e

@wifi_dut_marker()
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C708786')
def test_wifi_sdk_query_webpage_every_5secs_http_server_c708786(
        wifi_sniffer, wifi_dut, wifi_access_point, http_server, http_client, request, sniffer_filter, sl_collections,
        utf_constants):

    """Verify http webpage at client side for every 5seconds like refresh"""
    try:
        capture_filename = request.node.name
        index_path = "/data"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, http_server=http_server, http_client=http_client,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                            test_case='708786', index_path=index_path)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.http_functionality()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        raise e