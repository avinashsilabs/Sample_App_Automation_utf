import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
)
from utf.utils.logger import get_logger
import string
import random
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


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None, http_server=None
                 , http_client=None, sl_collections=None, sniffer_filter=None, utf_constants=None, index_path=None,
                 test_case=None):
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

        if self.test_case == '19235' or self.test_case == '528822' or self.test_case == '641388':
            self.wifi_dut.interfaces.wifi.http_server_init()

        if self.test_case == '564051':
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            self.wifi_dut.interfaces.wifi.http_server_init(send_large_data=1, data=data)

        self.wifi_dut.interfaces.wifi.http_server_start()

        logger().info(f"...... sending http get request from third party client to DUT .......")

        status, resp_content = self.http_client.interfaces.http.http_request(
            self.http_server.interfaces.http, method, self.index_path, server_ip=self.dut_addr['device_ip'], timeout=20)

        logger().info(f"........ length of DUT webpage {len(resp_content)} .......")
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


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DHCPv4Client,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}}
        }
    )
]


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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

