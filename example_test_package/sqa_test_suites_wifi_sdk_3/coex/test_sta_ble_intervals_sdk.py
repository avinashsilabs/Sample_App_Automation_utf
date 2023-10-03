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
    Si91xModuleType
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping


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
        5. set Region ,scan ,connect, data transfer

    Author: Swathi.Chinthala

"""

# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, test_type=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, region=None, switch=None):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, 5):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) > 0), "scan failed"
            time.sleep(5)

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                        protocol=self.protocol, device_ip=self.device_ip,
                                        host_ip=host_ip, timeout=100, traffic_type="TX")

    def join_to_ap(self):
        self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                 wifi_access_point=self.wifi_access_point,
                                                                 power_save=self.power_save,
                                                                 associated=self.wifi_dut.interfaces.wifi.associated,
                                                                 retry_count=3, ping_after_power_save=True,
                                                                 ping_count=self.ping_count)
        self.device_ip = self.dut_addr['device_ip']
        self.dut_mac_address = self.dut_addr['dut_mac_address']
        logger().info(f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************")
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

    def sniffer_validation_join(self):
        self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer, self.dut_mac_address,
                                               self.ap_mac_address, self.sniffer_filter,
                                               power_save=self.power_save)

    def sniffer_validation_scan(self):
            self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.\
                get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='probe_request')
            logger().info(f"Validating Probe req(Broadcast)")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter1)['packet_count'],\
                'Sniffer: Unable to find probe_request packets in sniffer'

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            status = ping(self.device_ip, 50)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            logger().info("Running data transfer")
            self.run_traffic()

        if self.test_type == "http":
            logger().info("http download")

        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()


# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, adv_int=None,
                 ble_scan_interval=None, ble_scan_window=None, sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        self.bt_dut_address = None
        self.ble_test_type = ble_test_type
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.sl_collections = sl_collections

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.bt_dut_address}")
        time.sleep(5)

    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()

    def stop_scan_adv(self):
        logger().info("Initiating stop scan from Remote dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()

    def run(self):

        if self.ble_test_type == "advertise":
            self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                  ble_adv_int_min=int(self.adv_int / 0.625),
                                                                  ble_adv_int_max=int(self.adv_int / 0.625),
                                                                  ble_dut_address=self.bt_dut_address,
                                                                  timeout=20)

        if self.ble_test_type == "scan":
            self.sl_collections.check_ble_scan_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                             ble_address=self.bt_dut_address,
                                                             ble_scan_interval=int(self.ble_scan_interval / 0.625),
                                                             ble_scan_window=int(self.ble_scan_window / 0.625),
                                                             timeout=60)

            logger().info(f"*****Logic Analyzer validation is pending*******")




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv"])
def test_Wifi_sdk_scan_BLE_AI_20ms_C20164(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, utf_constants,
                                      sl_collections, sniffer_filter, wifi_client):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. WLAN scan
          5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
          6. Wi-Fi scan with BLE advertise with interval 20ms
      """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "scan"
        logger().info(f"testcase : test_Wifi_scan_BLE_AI_20ms_C20164")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=20)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        ble_obj.start()
        wifi_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_sdk_connection_BLE_AI_20ms_C20165(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Join the access point and enable the dhcp
          3. Enable the wlan and bt power save mode in dut after the connection
          4. Initiate ping from the dut
          5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
          6. Wi-Fi connection and ping with BLE advertise with interval 20ms
      """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=20)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         testcase=test_name, wifi_client=wifi_client,
                                         sl_collections=sl_collections,
                                         ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_sdk_Data_BLE_AI_20ms_C20166(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                      net_perf_client, ble_client, protocol, request, utf_constants, sl_collections,
                                      sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Join the access point and enable the dhcp
          3. Enable the wlan and bt power save mode in dut after the connection
          4. Initiate ping from the dut
          5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
          6. Wi-Fi data transfer with BLE advertise with interval 20ms
      """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=20)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client
                                  , protocol=protocol, sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf")
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["ble_stop_adv"])
def test_Wifi_sdk_scan_BLE_AI_10240ms_C20167(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, utf_constants,
                                      sl_collections, sniffer_filter, wifi_client):
    """
                  Test Steps:
                      1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
                      2. wlan scan
                      5. Advertise DUT by setting advertise interval 10.24 secs and scan from remote BLE device
                      6. wlan scan with BLE advertise with interval 10.24s
                  """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "scan"
        logger().info(f"testcase : test_Wifi_scan_BLE_AI_20ms_C20164")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=10240)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        ble_obj.start()
        wifi_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_wifi_sdk_AP_conn_BLE_AI_10240ms_C20168(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
                  Test Steps:
                      1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
                      2. Join the access point and enable the dhcp
                      3. Enable the wlan and bt power save mode in dut after the connection
                      4. Initiate ping from the dut
                      5. Advertise DUT by setting advertise interval 10.24 secs and scan from remote BLE device
                      6. Wi-Fi connection and ping with BLE advertise with interval 10.24s
                  """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=10240)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         testcase=test_name, wifi_client=wifi_client,
                                         sl_collections=sl_collections,
                                         ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_sdk_Data_BLE_AI_10240ms_C20169(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                      net_perf_client, ble_client, protocol, request, utf_constants, sl_collections,
                                      sniffer_filter):
    """
              Test Steps:
                  1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
                  2. Join the access point and enable the dhcp
                  3. Enable the wlan and bt power save mode in dut after the connection
                  4. Initiate ping from the dut
                  5. Advertise DUT by setting advertise interval 10.24 secs and scan from remote BLE device
                  6. Wi-Fi data transfer with BLE advertise with interval 10.24s
              """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="advertise", adv_int=10240)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client
                                  , protocol=protocol, sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf")
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_sdk_scan_BLE_SI_10240ms_SW_3440ms_C20173(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, wifi_client,
                                                   request, utf_constants, sl_collections, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. wlan scan continuously
               5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
               6. Wi-Fi continuous scan with BLE scan interval of 10240ms and scan window of 3440ms
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="scan")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=10240, ble_scan_window=3440)
        ble_obj.start()
        wifi_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_sdk_AP_conn_BLE_SI_10240ms_SW_3440ms_C20174(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                          request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Join the access point and enable the dhcp
               3. Enable the wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
               5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
               6. Wi-Fi connection and ping with BLE scan interval of 10240ms and scan window of 3440ms
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=10240, ble_scan_window=3440)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_Data_BLE_SI_10240ms_SW_3440ms_C20175(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                   net_perf_client, ble_client, protocol, request, utf_constants,
                                                   sl_collections, sniffer_filter):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Join the access point and enable the dhcp
            3. Enable the wlan and bt power save mode in dut after the connection
            4. Initiate ping from the dut
            5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
            6. Wi-Fi data transfer with BLE scan interval of 10240ms and scan window of 3440ms
        """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=10240, ble_scan_window=3440)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client
                                  , protocol=protocol, sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf")
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_sdk_scan_BLE_SI_7_5ms_SW_2_5ms_C20170(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, wifi_client,
                                                   request, utf_constants, sl_collections, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. wlan scan continuously
               5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
               6. Wi-Fi continuous scan with BLE scan interval of 10240ms and scan window of 3440ms
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="scan")
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=7.5, ble_scan_window=2.5)
        ble_obj.start()
        wifi_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}}

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_sdk_AP_conn_BLE_SI_7_5ms_SW_2_5ms_C20171(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                       request, utf_constants, sl_collections, wifi_client,
                                                       sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Join the access point and enable the dhcp
               3. Enable the wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
               5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
               6. Wi-Fi connection and ping with BLE scan interval of 10240ms and scan window of 3440ms
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=7.5, ble_scan_window=2.5)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.join_to_ap()

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}, "ble": {"count": 2, "stack_len": 2048}}

    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_sdk_Data_BLE_SI_7_5ms_SW_2_5ms_C20172(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                    net_perf_client, ble_client, protocol, request, utf_constants,
                                                    sl_collections, sniffer_filter):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Join the access point and enable the dhcp
            3. Enable the wlan and bt power save mode in dut after the connection
            4. Initiate ping from the dut
            5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
            6. Wi-Fi data transfer with BLE scan interval of 10240ms and scan window of 3440ms
        """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_interval=7.5, ble_scan_window=2.5)
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  protocol=protocol, sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf")
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




