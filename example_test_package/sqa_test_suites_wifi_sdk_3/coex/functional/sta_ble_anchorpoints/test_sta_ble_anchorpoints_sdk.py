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
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Si917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Intel NUC(Wireless Sniffer)

    Test Steps:
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. DO HTTP data transfer
        6. BLE advertise, connect, update connection interval, latency, LSTO

    Author: Hari Bhargav Nalla

"""

# this thread used for Wi-Fi join
class WifiThread(ThreadBase):
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

    def run_http_download(self):
        logger().info("in http download method")
        # File download through HTTP method
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
                # Configure Listen interval based power save in join feat bitmap
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
            # Get BSSID of AP
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


    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def run(self):

        if self.test_type == "ping":
            self.join_to_ap()
            status = ping(self.device_ip, 50)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "http":
            if not self.wifi_dut.interfaces.wifi.associated:
                self.join_to_ap()
            self.run_http_download()


# this thread used for BLE functionality
class BleThreadFunctionality(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        adv_int=None,
        ble_scan_interval=None,
        ble_scan_window=None,
        sl_collections=None,
        ble_pairing=0,
        min_conn_int=None,
        max_conn_int=None,
        conn_latency=None,
        supervision_timeout=None,

    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        self.ble_dut_address = None
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.min_conn_int = min_conn_int
        self.max_conn_int = max_conn_int
        self.conn_latency = conn_latency
        self.supervision_timeout = supervision_timeout

        # Set up DUT for BLE advertising
        logger().info("Initializing BLE")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"ble_dut_address : {self.ble_dut_address}")
        time.sleep(5)

    def ble_disconnect(self, disconnect_from="remote"):
        # This method will trigger BLE disconnection from Raspberry Pi
        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from,
            ble_client_address=self.ble_client_address,
        )

    def ble_conn_param_update(self):

        logger().info("updating connection params")
        self.ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(dev_addr=self.ble_dut_address,
                                                                          min_conn_interval=int(
                                                                              int(self.min_conn_int) / 1.25),
                                                                          max_conn_interval=int(
                                                                              int(self.max_conn_int) / 1.25),
                                                                          conn_latency=self.conn_latency,
                                                                          supervision_timeout=int(self.supervision_timeout)/10)

    def conn_param_update_check(self, btmon_file_name, search_strings):
        con_flag = None
        # Opening the btmon log and searching for the required strings in it
        with open(btmon_file_name, "r") as file_p:
            # Iterate over each line in the file
            for data_line in file_p:
                # Search for this string in the file
                if "LE Connection Update Complete (0x03)" in data_line:
                    con_flag = 1
                    break
            if con_flag:
                logger().info("\n******* Found LE Connection Update Complete string in bt_mon log *******\n")
            else:
                assert (con_flag), "******LE Connection Update Complete string not found******"

        try:
            # Open the file for reading
            with open(btmon_file_name, 'r') as file:
                # Iterate over each line in the file
                for line in file:
                    if line == "LE Connection Update Complete (0x03)":
                        break
                    # Search for each string
                    for search_string in search_strings:
                        if search_string in line:
                            logger().info(f"\n*******{search_string}' found*******\n")
        except FileNotFoundError:
            logger().info(f"*******Error: The file '{btmon_file_name}' was not found*******")
            return None
        except IOError:
            logger().info(f"*******Error: Could not read the file '{btmon_file_name}'*******")
            return None

    def run(self):

        # Advertise DUT-BLE
        self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                        ble_dut_address=self.ble_dut_address, timeout=20)
        self.wifi_dut.interfaces.wifi.ble_scanning = False
        self.wifi_dut.interfaces.wifi.ble_advertising = False
        # Initiate BLE SMP pairing
        self.ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=self.ble_dut_address)
        logger().info("BLE Connection success")

pytestmark = [
 pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE ,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096, "priority": 8},
            "ble": {"count": 1, "stack_len": 4096},
        },
    },
 )
]

@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_15ms_latency_5_LSTO_4s_C20122(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 15
        max_connection_interval = 15
        connection_latency = 5
        supervision_timeout = 4000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20122_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 15.00 msec (0x000c)",
            "Connection latency: 5 (0x0005)",
            "Supervision timeout: 4000 msec (0x0190)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_240ms_latency_5_LSTO_4s_C20123(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 240
        max_connection_interval = 240
        connection_latency = 5
        supervision_timeout = 4000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20123_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 240.00 msec (0x00c0)",
            "Connection latency: 5 (0x0005)",
            "Supervision timeout: 4000 msec (0x0190)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_250ms_latency_2_LSTO_32s_C20124(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 250
        max_connection_interval = 250
        connection_latency = 2
        supervision_timeout = 32000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20124_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 250.00 msec (0x00c8)",
            "Connection latency: 2 (0x0002)",
            "Supervision timeout: 32000 msec (0x0c80)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_15ms_latency_0_LSTO_4s_C20125(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 15
        max_connection_interval = 15
        connection_latency = 0
        supervision_timeout = 4000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20125_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 15.00 msec (0x000c)",
            "Connection latency: 0 (0x0000)",
            "Supervision timeout: 4000 msec (0x0190)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_250ms_latency_0_LSTO_32s_C20126(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 250
        max_connection_interval = 250
        connection_latency = 0
        supervision_timeout = 32000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20122_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 250.00 msec (0x00c8)",
            "Connection latency: 0 (0x0000)",
            "Supervision timeout: 32000 msec (0x0c80)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_50ms_latency_5_LSTO_16s_C20180(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 50
        max_connection_interval = 50
        connection_latency = 5
        supervision_timeout = 16000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20180_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 50.00 msec (0x0028)",
            "Connection latency: 5 (0x0005)",
            "Supervision timeout: 16000 msec (0x0640)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_WiFi_sdk_wifi_http_download_BLE_CI_50ms_latency_0_LSTO_10s_C20181(
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
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. Do file download through HTTP
        6. BLE advertise, connect, update connection interval 15ms, latency 5 and LSTO 4000ms
        7. Check the BLE connection stability
    """

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
        min_connection_interval = 50
        max_connection_interval = 50
        connection_latency = 0
        supervision_timeout = 10000
        dev_state = 8

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
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

        # btmon logs will be redirected to this file
        bt_mon_log_file = (f"reports/test_sta_ble_anchorpoints_sdk_C20181_{int(time.time())}.log"
        )
        ble_obj = BleThreadFunctionality(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                min_conn_int=min_connection_interval,
                max_conn_int=max_connection_interval,
                conn_latency=connection_latency,
                supervision_timeout=supervision_timeout,
                ble_pairing=1,
        )

        # Associate to Access point
        wifi_obj.join_to_ap()

        # Start BLE advertise followed by Raspi connection with DUT over BLE
        ble_obj.start()
        ble_obj.wait_for_exit()

        # Get the BLE device state of DUT
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == dev_state, "DUT BLE device is not in connected state"

        # Start btmon logs capture
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file):
            # Update the BLE connection parameters
            ble_obj.ble_conn_param_update()

        search_strings = [
            "Connection interval: 50.00 msec (0x0028)",
            "Connection latency: 0 (0x0000)",
            "Supervision timeout: 10000 msec (0x03e8)"
        ]
        ble_obj.conn_param_update_check(bt_mon_log_file, search_strings)

        # Start file download through HTTP
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Initiate BLE disconnection
        ble_obj.ble_disconnect()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # start Sniffer validation for wifi join
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the Raspi BLE
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)