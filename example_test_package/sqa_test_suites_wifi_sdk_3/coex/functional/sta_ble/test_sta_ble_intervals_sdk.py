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
    Si91xJoinFeatureBitMap
)
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
import random
import string
from random import randint



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

ble_obj = None

# this thread used for Wi-Fi join
class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
        self,
        wifi_sniffer=None,
        wifi_dut=None,
        wifi_access_point=None,
        testcase=None,
        wifi_client=None,
        net_perf_client=None,
        protocol=None,
        test_type=None,
        sl_collections=None,
        ping_count=None,
        sniffer_filter=None,
        region=None,
        switch=None,
        http_server=None,
        index_path=None,
        https=0
    ):

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
        self.http_server = http_server
        self.index_path = index_path
        self.https = https
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):

        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            # scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                                 channel=0)
            logger().info(f"scan results : {scan_results}")
            time.sleep(5)

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=host_ip,
            timeout=100,
            traffic_type="TX",
        )

    def run_http_download(self):
        logger().info("in http download method")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=self.device_ip,
            https=self.https,
        )

    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            logger().info("Enabling rejoin parameters")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=4,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            if self.power_save:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                  Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=self.power_save,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                ping_after_power_save=True,
                ping_count=self.ping_count,
            )
            self.device_ip = self.dut_addr["device_ip"]
            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")

    def sniffer_validation_join(self):
        self.sl_collections.join_sniffer_validation(
            self.wifi_access_point,
            self.wifi_sniffer,
            self.dut_mac_address,
            self.ap_mac_address,
            self.sniffer_filter,
            power_save=self.power_save,
        )

        if self.power_save:
            packet_filter1 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address, filter_name="ps_poll"
                )
            )
            logger().info(f"Validating PS-POLL frames ")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter1
            )["packet_count"], "Sniffer: Unable to find ps poll packets in sniffer"
            packet_filter2 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="qos_data_more_data",
                )
            )
            logger().info(f"Validating QOS data frames with more data bit set")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find QOS data frames with more data bit set in sniffer"

    def sniffer_validation_scan(self):
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="probe_request"
            )
        )
        logger().info(f"Validating Probe req(Broadcast)")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Sniffer: Unable to find probe_request packets in sniffer"

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            self.join_to_ap()
            status = ping(self.device_ip, 50)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            self.join_to_ap()
            status = ping(self.device_ip, 10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
            logger().info("Running data transfer")
            self.run_traffic()

        if self.test_type == "http":
            if not self.wifi_dut.interfaces.wifi.associated:
                self.join_to_ap()
            self.run_http_download()




def cleanup_ble(ble_client, ble_dut_address):
    status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
    if status:
        logger().info(f"Initiating BLE disconnection from raspi")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    ble_client.interfaces.bluetooth.close()





# this thread used for sta+ble as a slave
class BleThreadFunctionality(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        ble_test_type=None,
        adv_int=None,
        ble_scan_interval=None,
        ble_scan_window=None,
        sl_collections=None,
        ble_pairing=0,
        set_smp=0,
        conn_int=160,

    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.conn_int = conn_int
        self.set_smp = set_smp

        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        # self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=self.set_smp)
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"ble_dut_address : {self.ble_dut_address}")
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

    def advertise_dut(self):

        logger().info(f"Advertising the DUT")

        self.wifi_dut.interfaces.wifi.ble_start_advertising(
            ble_adv_int_min=int(self.adv_int / 0.625),
            ble_adv_int_max=int(self.adv_int / 0.625),
            timeout=20,
        )

    def ble_disconnect(self, disconnect_from="remote"):

        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from,
            ble_client_address=self.ble_client_address,
        )


    def run(self):

        if self.ble_test_type == "advertise":

            logger().info("Initiating scan from Remote device")
            # Begin Scanning for BLE devices
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut_address
            )
            assert (
                self.ble_client_address is not None
            ), "Unable to fetch bluetooth address from Remote device"
            logger().info(f"Started scan from remote BLE device")
            logger().info("\n***********{}**********\n".format(self.ble_client_address))
            for i in range(0, 3):
                time.sleep(20)
                if self.adv_int > 1000:
                    time.sleep(20)
                # See that we found our device
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                logger().info("\n***scan results:{}**********\n".format(found_devices))
            assert (
                self.wifi_dut.interfaces.wifi.ble_address in found_devices
            ), "DUT not found in scan results"
            logger().info(
                f"DUT BLE address:'{self.ble_dut_address}' found in raspi scan results"
            )
            return self.ble_client_address

        if self.ble_test_type == "scan":
            self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_address=self.ble_dut_address,
                ble_scan_interval=int(self.ble_scan_interval / 0.625),
                ble_scan_window=int(self.ble_scan_window / 0.625),
                timeout=60,
            )

            logger().info(f"*****Logic Analyzer validation is pending*******")

        if self.ble_test_type == "slave" or self.ble_test_type == "master":
            self.ble_client_address = self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                mode=self.ble_test_type,
                ble_pairing=self.ble_pairing,
                min_conn_interval=self.conn_int, max_conn_interval=self.conn_int,
                conn_latency=0, supervision_timeout=3000, timeout=30
            )


def wifi_dut_marker(ext_custom_bit=0, tcp_feat_bit=0, ext_tcp_feat_bit=0, ca_cert=None, wifi_stack_len=4095,
                    ble_stack_len=2048):
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
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_Wifi_sdk_scan_BLE_AI_20ms_C20164(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    wifi_client,
):
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
            ble_test_type="advertise",
            adv_int=20,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_connection_BLE_AI_20ms_C20165(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
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
            ble_test_type="advertise",
            adv_int=20,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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



@wifi_dut_marker()
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_BLE_AI_20ms_C20166(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=20,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_Wifi_sdk_scan_BLE_AI_10240ms_C20167(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    wifi_client,
):
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
            ble_test_type="advertise",
            adv_int=10240,
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
        )
        ble_obj.advertise_dut()
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_wifi_sdk_AP_conn_BLE_AI_10240ms_C20168(
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
        5. Advertise DUT by setting advertise interval 10.24 secs and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 10.24s
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
            ble_test_type="advertise",
            adv_int=10240,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_BLE_AI_10240ms_C20169(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=10240,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_scan_BLE_SI_10240ms_SW_3440ms_C20173(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_scan_interval=10240,
            ble_scan_window=3440,
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
            test_type="scan",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_AP_conn_BLE_SI_10240ms_SW_3440ms_C20174(
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
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi connection and ping with BLE scan interval of 10240ms and scan window of 3440ms
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
            ble_test_type="scan",
            ble_scan_interval=10240,
            ble_scan_window=3440,
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
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_Data_BLE_SI_10240ms_SW_3440ms_C20175(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_scan_interval=10240,
            ble_scan_window=3440,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_scan_BLE_SI_7_5ms_SW_2_5ms_C20170(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_scan_interval=7.5,
            ble_scan_window=2.5,
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
            test_type="scan",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_AP_conn_BLE_SI_7_5ms_SW_2_5ms_C20171(
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
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi connection and ping with BLE scan interval of 10240ms and scan window of 3440ms
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
            ble_test_type="scan",
            ble_scan_interval=7.5,
            ble_scan_window=2.5,
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
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_BLE_SI_7_5ms_SW_2_5ms_C20172(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_scan_interval=7.5,
            ble_scan_window=2.5,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_scan_BLE_SI_10240ms_SW_5000ms_C148613(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. wlan scan continuously
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi continuous scan with BLE scan interval of 10240ms and scan window of 5000ms
    """
    try:
        test_name = request.node.name
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
            ble_scan_interval=10240,
            ble_scan_window=5000,
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
            test_type="scan",
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
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
def test_Wifi_sdk_wifi_http_download_BLE_AI_20ms_C20176(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
        7. Download http file
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
            ble_test_type="advertise",
            adv_int=20,
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
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
def test_Wifi_sdk_wifi_http_download_BLE_AI_10240ms_C20177(
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
        5. Advertise DUT by setting advertise interval 10240ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
        7. Download http file
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
            ble_test_type="advertise",
            adv_int=10240,
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
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
def test_Wifi_sdk_wifi_http_download_BLE_SI_7_5ms_SW_2_5ms_C20178(
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
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi connection and ping with BLE scan interval of 7.5ms and scan window of 2.5ms
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
            ble_test_type="scan",
            ble_scan_interval=7.5,
            ble_scan_window=2.5,
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
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
def test_Wifi_sdk_wifi_http_download_BLE_SI_10240ms_SW_3440ms_C20179(
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
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi connection and ping with BLE scan interval of 10.24s and scan window of 3.440s
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
            ble_test_type="scan",
            ble_scan_interval=10240,
            ble_scan_window=3440,
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_http_download_BLE_SI_10240ms_SW_5000ms_C148614(
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
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi connection and ping with BLE scan interval of 10.24s and scan window of 5s
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
            ble_test_type="scan",
            ble_scan_interval=10240,
            ble_scan_window=5000,
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_500ms_peripheral_C537981(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=500,
            ble_pairing=1,
            set_smp =0
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_1000ms_peripheral_C537982(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=1000,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_500ms_central_C537983(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            conn_int=500,
            ble_pairing=1,
            set_smp=1
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_1000ms_central_C537984(
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
        5. connect DUT as BLE master with smp with connection interval 1000ms
        6. Download http file
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
            conn_int=1000,
            ble_pairing=1,
            set_smp=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_45ms_peripheral_C538015(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=45,
            ble_pairing=1
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

        ble_dut_addr = ble_obj.ble_dut_address
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_500ms_peripheral_C538016(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""
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
            ble_test_type="slave",
            conn_int=500,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_dut_addr = ble_obj.ble_dut_address
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_1000ms_peripheral_C538017(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=1000,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_dut_addr = ble_obj.ble_dut_address
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_scan_BLE_SI_1000ms_SW_100ms_C537945(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. wlan scan continuously
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi continuous scan with BLE scan interval of 1000ms and scan window of 100ms
    """
    try:
        test_name = request.node.name
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
            ble_scan_interval=1000,
            ble_scan_window=100,
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
            test_type="scan",
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_scan()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_scan_BLE_SI_160ms_SW_40ms_C537978(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. wlan scan continuously
        5. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        6. Wi-Fi continuous scan with BLE scan interval of 160ms and scan window of 40ms
    """
    try:
        test_name = request.node.name
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
            ble_scan_interval=160,
            ble_scan_window=40,
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
            test_type="scan",
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
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



@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_sdk_SSL_RX_BLE_SI_1000ms_SW_100ms_C537949(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    wifi_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    ssl_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. join to the access point and enable the dhcp
        3. Advertise remote BLE device and scan from DUT by setting scan interval and scan window
        4. Wi-Fi continuous scan with BLE scan interval of 1000ms and scan window of 100ms
        5.
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
            ble_test_type="scan",
            ble_scan_interval=1000,
            ble_scan_window=100,
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
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=sock)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger().info("Initiating wlan disconnect from DUT")
        ble_obj.stop_scan_adv()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, wifi_obj.dut_mac_address, ["tls"], test_name,
                                             wifi_obj.ap_mac_address)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

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
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_https_download_BLE_CI_250ms_central_C537989(
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
        5. connect DUT as BLE master with smp with connection interval 250ms
        6. Download http file
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
            conn_int=250,
            ble_pairing=1,
            set_smp=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_https_download_BLE_CI_4000ms_central_C537990(
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
        5. connect DUT as BLE master with smp with connection interval 250ms
        6. Download http file
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
            conn_int=4000,
            ble_pairing=1,
            set_smp=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_45ms_peripheral_C537986(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=45,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_500ms_peripheral_C537987(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=500,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_1000ms_peripheral_C537988(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=1000,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_scan_BLE_AI_50ms_C780232(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    wifi_client,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. WLAN scan
        5. Advertise DUT by setting advertise interval 20 ms and scan from remote BLE device
        6. Wi-Fi scan with BLE advertisement with interval 20 ms
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "scan"
        logger().info(f"testcase : test_Wifi_scan_BLE_AI_20ms_C20164")
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
            ble_test_type="advertise",
            adv_int=50,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_Wifi_sdk_scan_BLE_AI_80ms_C780233(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    wifi_client,
):
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
            ble_test_type="advertise",
            adv_int=80,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
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

@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_Wifi_sdk_scan_BLE_AI_120ms_C780234(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
    wifi_client,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. WLAN scan
        5. Advertise DUT by setting advertise interval 120ms and scan from remote BLE device
        6. Wi-Fi scan with BLE advertise with interval 120ms
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = utf_constants.get("iter_count")
        test_type = "scan"
        logger().info(f"testcase : test_Wifi_scan_BLE_AI_20ms_C20164")
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
            ble_test_type="advertise",
            adv_int=120,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        logger().info("stopping capture")
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




@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_connection_BLE_AI_50ms_C780235(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
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
            ble_test_type="advertise",
            adv_int=50,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_connection_BLE_AI_80ms_C780236(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
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
            ble_test_type="advertise",
            adv_int=80,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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


@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_connection_BLE_AI_120ms_C780237(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
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
            ble_test_type="advertise",
            adv_int=120,
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
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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


@wifi_dut_marker()
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_UDP_BLE_AI_50ms_C780238(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=50,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_UDP_BLE_AI_80ms_C780239(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=80,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_UDP_BLE_AI_120ms_C780240(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=120,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_TCP_BLE_AI_50ms_C780241(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=50,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_TCP_BLE_AI_80ms_C780242(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=80,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_Data_TCP_BLE_AI_120ms_C780243(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    wifi_client,
    net_perf_client,
    ble_client,
    protocol,
    request,
    utf_constants,
    sl_collections,
    sniffer_filter,
):
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
            ble_test_type="advertise",
            adv_int=120,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            protocol=protocol,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        wifi_obj.disconnect()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
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
def test_Wifi_sdk_wifi_http_download_BLE_AI_50ms_C780244(
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
        5. Advertise DUT by setting advertise interval 20ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
        7. Download http file
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
            ble_test_type="advertise",
            adv_int=50,
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
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
def test_Wifi_sdk_wifi_http_download_BLE_AI_80ms_C780245(
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
        5. Advertise DUT by setting advertise interval 10240ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
        7. Download http file
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
            ble_test_type="advertise",
            adv_int=80,
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
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
def test_Wifi_sdk_wifi_http_download_BLE_AI_120ms_C780246(
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
        5. Advertise DUT by setting advertise interval 10240ms and scan from remote BLE device
        6. Wi-Fi connection and ping with BLE advertise with interval 20ms
        7. Download http file
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
            ble_test_type="advertise",
            adv_int=120,
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
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_30ms_peripheral_C780247(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=30,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_80ms_peripheral_C780248(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=80,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_http_download_BLE_CI_150ms_peripheral_C780249(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=150,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_30ms_peripheral_C780250(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=30,
            ble_pairing=1
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

        ble_dut_addr = ble_obj.ble_dut_address
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_80ms_peripheral_C780251(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""
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
            ble_test_type="slave",
            conn_int=80,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_dut_addr = ble_obj.ble_dut_address
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
def test_Wifi_sdk_wifi_time_for_http_download_BLE_CI_150ms_peripheral_C780252(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
    """
    ble_dut_addr = ""

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
            ble_test_type="slave",
            conn_int=150,
            ble_pairing=1
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

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_dut_addr = ble_obj.ble_dut_address
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_30ms_peripheral_C780253(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=30,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_80ms_peripheral_C780254(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=80,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated"]
)
def test_Wifi_sdk_wifi_time_for_https_download_BLE_CI_150ms_peripheral_C780255(
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
        5. connect DUT as BLE master with smp with connection interval 500ms
        6. Download http file
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
            ble_test_type="slave",
            conn_int=150,
            ble_pairing=1
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
            index_path=index_path,
            https=1
        )
        wifi_obj.join_to_ap()

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

