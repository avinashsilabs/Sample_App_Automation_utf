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
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.time_measurer import TimeMeasurer





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

        if not self.wifi_dut.interfaces.wifi.associated:

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
        if self.power_save:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='ps_poll')
            logger().info(f"Validating ps polls in sniffer")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter1)['packet_count'], \
                'Sniffer: Unable to find ps-polls in sniffer'

    def sniffer_validation_scan(self):
            self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.\
                get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='probe_request')
            logger().info(f"Validating Probe req(Broadcast)")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter1)['packet_count'],\
                'Sniffer: Unable to find probe_request packets in sniffer'

    def sniffer_validation_powersave(self):
        if self.power_save:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=self.dut_mac_address, filter_name='ps_poll')
            logger().info(f"Validating ps polls in sniffer")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter1)['packet_count'], \
                'Sniffer: Unable to find ps-polls in sniffer'

            packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address, filter_name='power_mgmt_bit')
            logger().info(f"Validating ps polls in sniffer")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=
                                                                           packet_filter2)['packet_count'], \
                'Sniffer: Unable to find power_mgmt_bit in sniffer'


    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            self.join_to_ap()
            status = ping(self.device_ip, 300)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic()

        if self.test_type == "throughput":
            self.join_to_ap()
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            # self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
            #                                 protocol="TCP", device_ip=self.device_ip,
            #                                 host_ip=host_ip, timeout=100, traffic_type="TX")
            self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
                                            protocol="TCP", device_ip=self.device_ip,
                                            host_ip=host_ip, timeout=50, traffic_type="TX")
            # self.sl_collections.run_traffic(wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client,
            #                                 protocol="UDP", device_ip=self.device_ip,
            #                                 host_ip=host_ip, timeout=100, traffic_type="TX")


        if self.test_type == "http":
            self.join_to_ap()
            logger().info("http download")

        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()




# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, ble_scan_type=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.bt_dut_address}")
        time.sleep(5)
        self.ble_client_address = None

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

    def ble_disconnect(self, disconnect_from="remote"):
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)


    def run(self):
        if self.ble_test_type == "advertise":
            self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                  ble_dut_address=self.bt_dut_address,
                                                                  timeout=20)

        if self.ble_test_type == "scan":
            self.sl_collections.check_ble_scan_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                             ble_address=self.bt_dut_address,
                                                             ble_scan_type=self.ble_scan_type,
                                                             timeout=60)
        if self.ble_test_type == "slave":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.bt_dut_address,
                                                                         mode="slave")

        if self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(wifi_dut=self.wifi_dut,
                                                                         ble_client=self.ble_client,
                                                                         ble_dut_address=self.bt_dut_address,
                                                                         mode="master")


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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_sdk_coex_fun_ble_slave_wlan_conn_C133428(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Conenct DUT as BLE slave
          3. Join the access point and enable the dhcp
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Initiate ping from the dut

      """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                     ble_test_type="slave")
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client,
                              sl_collections=sl_collections,
                              ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.ble_disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")




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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_sdk_coex_fun_ble_master_wlan_conn_C133429(wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
                                                utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
      Test Steps:
          1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
          2. Conenct DUT as BLE master
          3. Join the access point and enable the dhcp
          4. Enable the wlan and bt power save mode in dut after the connection
          5. Initiate ping from the dut

      """
    test_name = request.node.name
    ping_count = utf_constants.get("ping_count")
    test_type = "ping"
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                     ble_test_type="master")
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client,
                              sl_collections=sl_collections,
                              ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.ble_disconnect(disconnect_from="dut")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")





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
def test_Coex_sdk_WLAN_conn_while_BLE_scan_C133430(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Scan from DUT check whether dut is able to find remote device
               2. Join the access point and enable the dhcp
               3. Enable the wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
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
                                         ble_test_type="scan")
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Coex_sdk_BLE_conn_request_WLAN_conn_C133431(wifi_dut, wifi_sniffer, wifi_access_point,  ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Scan from DUT check whether dut is able to find remote device
               4. Initiate connection request from DUT to remote device
               5. Join the access point and enable the dhcp
               6. Enable the wlan and bt power save mode in dut after the connection
               7. Initiate ping from the dut
           """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info(
            "\n******* Validating the LE connection complete print in bt_mon logs as there is no BT sniffer support currently  *******")
        logger().info("\n*******btmon started*******")
        bt_mon_log_file_name = f"reports/ble_conn_req_wlan_connection_C133431_{int(time.time())}.log"
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=bt_mon_log_file_name):
            ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                             ble_test_type="master")
            ble_obj.start()
            ble_obj.wait_for_exit()

        # Opening the btmon log and searching for the required strings in it
        with open(bt_mon_log_file_name, "r") as file_p:
            for data_line in file_p:
                if "LE Connection Complete (0x01)" in data_line:
                    con_flag = 1
                if "Slave (0x01)" in data_line:
                    role_flag = 1
                    break
            if con_flag and role_flag:
                logger().info(
                    "\n******* Found LE Connection Complete (0x01) and Slave (0x01) strings in bt_mon logs *******")
            else:
                assert con_flag, "******LE Connection Complete (0x01) string not found******"
                assert role_flag, "******Slave (0x01) string not found******"

        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
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
def test_Coex_sdk_WLAN_conn_while_BLE_active_scan_C133432(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable active Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable the wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut
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
                                         ble_test_type="scan", ble_scan_type=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_conn_while_BLE_passive_scan_C133433(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise remote Raspi device
               3. Enable passive Scan from DUT check whether dut is able to find remote device
               4. Join the access point and enable the dhcp
               5. Enable wlan and bt power save mode in dut after the connection
               6. Initiate ping from the dut
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
                                         ble_test_type="scan", ble_scan_type=0)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_scan_BLE_scan_C133445(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                             request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Initiate BLE scan from DUT and check whether dut is able to find remote device
               3. Initiate WLAN scan from DUT and check whether dut is able to find remote device
           """

    try:
        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan", ble_scan_type=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_type="scan")
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()
        logger().info("sniffer validation is successful")

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
def test_Coex_sdk_BLE_scan_while_WLAN_conn_C133568(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                   request, utf_constants, sl_collections, wifi_client, sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Join the access point and enable the dhcp
               3. Enable wlan and bt power save mode in dut after the connection
               4. Initiate ping from the dut
               5. Advertise remote Raspi device
               6. Scan from DUT check whether dut is able to find remote device
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)

        wifi_obj.join_to_ap()
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_test_type="scan")
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Coex_sdk_WLAN_throughput_open_BLE_slave_C133449(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, net_perf_client, protocol):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Join the access point and enable the dhcp
               5. Enable wlan and bt power save mode in dut after the connection
               6. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
           """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
        #                                  ble_test_type="slave")
        # ble_obj.start()
        # ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=test_name, wifi_client=wifi_client,
                                  sl_collections=sl_collections, net_perf_client=net_perf_client, protocol=protocol,
                                  ping_count=ping_count, sniffer_filter=sniffer_filter, test_type=test_type)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
       # ble_obj.ble_disconnect()
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Coex_sdk_all_channels_scan_time_BLE_adv_C133453(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter):
    """
           Test Steps:
               1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
               2. Advertise BLE DUT
               3. Scan from remote BLE device and connect to DUT
               4. Wlan Scan in all channels from DUT and calculate time taken to scan in all channels
           """


