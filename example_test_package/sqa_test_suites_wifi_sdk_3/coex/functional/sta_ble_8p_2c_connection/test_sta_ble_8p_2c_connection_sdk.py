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
)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.utils import print_dict


def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

class WifiJoinThread(ThreadBase):
    dut_addr = None

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            testcase=None,
            net_perf_client=None,
            data_transfer=True,
            traffic_type=None,
            iteration_count=None,
            protocol=None,

            host_ip=None):
        super().__init__()
        #here defined_DM
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.host_ip = host_ip
        self.dut_addr = None
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.iteration_count = iteration_count
        self.protocol = protocol


    def run(self):
        self.dut_addr = self.sl_collections.join_to_wifi_network(
            self.wifi_dut, self.wifi_access_point, associated=self.wifi_dut.interfaces.wifi.associated, ping_count=300)

    def iperf(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.dut_addr['device_ip'],
                                                             protocol='0x00')

        self.net_perf_client.interfaces.net_perf.start()

        logger().info("sending data from DUT")

        timeout = 40

        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0)

        logger().info(f"***** get and print throughput ******")
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        self.__print_throughput(tp)
        logger().info("data transfer is successful")


class BleThreadFunctionality(ThreadBase):
    ble_client_address = {}

    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None,
                 ble_dut=None, utf_constants=None, ble_dut_address=None, ble_client_address=None,
                 ble_clients=None, ble_conn_interval_min=160, ble_conn_interval_max=160, set_smp=0, ble_scan_window =None, ble_scan_interval=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_client_address = ble_client_address
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.utf_constants = utf_constants
        self.ble_clients = ble_clients
        self.ble_conn_interval_min = ble_conn_interval_min
        self.ble_conn_interval_max = ble_conn_interval_max
        self.set_smp = set_smp
        self.ble_scan_window = ble_scan_window
        self.ble_scan_interval = ble_scan_interval

        """ **************** Set up DUT for BLE advertising **************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)

        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def run(self):
        if self.test_case in [769615, 769616, 769617]:
            svc = 'HealthThermometerService'
            logger().info("******************** initializing ble in remote device ********************")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address, service_classes=[svc])
            assert self.ble_client_address, "failed to initialize ble in remote device"

            logger().info("******************** start scanning in dut ********************")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                             timeout=100, ble_scan_interval=self.ble_scan_interval, ble_scan_window= self.ble_scan_window)

            time.sleep(5)
            self.ble_client.interfaces.bluetooth.close()
            self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                timeout=20, ble_adv_int_min=self.ble_conn_interval_min, ble_adv_int_max=self.ble_conn_interval_max)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
                        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                                  | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                                  | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                                  | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
            "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                               | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
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
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
]
@pytest.mark.end_state(
    "wifi_dut", wifi=['ble_stop_adv', 'ble_stop_scan'])
def test_Coex_sdk_ble_adv_scan_wlan_scan_C769615(wifi_dut, utf_constants, sl_collections, ble_client, ble_dut):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. enable wifi scan
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT

    """
    try:
        logger().info("\n\n************************* Initiating wlan_scan from DUT ****************************")
        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(f"\n***************** wlan_scan successful in {t.duration} seconds *****************\n")
        time.sleep(3)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         ble_scan_interval=53, ble_scan_window=23, set_smp=1, ble_conn_interval_min=338,
                                         ble_conn_interval_max=338, test_case=769615)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        logger().error(f"Error in BLE thread functionality: {error}")
        raise error




@pytest.mark.end_state(
    "wifi_dut", wifi=['ble_stop_adv', 'ble_stop_scan'])
def test_Coex_sdk_ble_adv_scan_wlan_ping_C769616(wifi_dut, utf_constants, sl_collections, ble_client, ble_dut,
                                                 wifi_access_point, wifi_client, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. enable wifi scan & connect to AP
        3. Enable power save and then start ping from remote device.
        4. Advertise DUT ,Scan from remote device
        5. Advertise remote device & Scan from DUT

    """
    try:

        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
            sl_collections=sl_collections, sniffer_filter=sniffer_filter, ping_count=300)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         ble_scan_interval=48, ble_scan_window=16, set_smp=1, ble_conn_interval_min=32, ble_conn_interval_max=32,
                                         test_case=769616)

        wifi_obj.start()
        time.sleep(20)  # Wait for WiFi to connect and ping to start
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()

    except Exception as error:
        logger().error(f"Error in BLE thread functionality: {error}")
        raise error

@pytest.mark.end_state(
    "wifi_dut", wifi=['ble_stop_adv', 'ble_stop_scan'])
def test_Coex_sdk_ble_adv_scan_then_wlan_ping_C769617(wifi_dut, utf_constants, sl_collections, ble_client, ble_dut,
                                                 wifi_access_point, wifi_client, sniffer_filter):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Advertise DUT ,Scan from remote device enable
            3. Advertise remote device & Scan from DUT
            4. Wifi scan & connect to AP
            5. Enable power save and then start ping from remote device.

        """
    try:


        wifi_obj = WifiJoinThread(
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
            sl_collections=sl_collections, sniffer_filter=sniffer_filter, ping_count=300)

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         ble_scan_interval=384, ble_scan_window=128, set_smp=1, ble_conn_interval_min=48, ble_conn_interval_max=48,
                                         test_case=769617)
        ble_obj.start()

        time.sleep(20)  # Wait for WiFi to connect and ping to start
        wifi_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        logger().info("Test completed successfully.")
    except Exception as error:
        logger().error(f"Error in BLE thread functionality: {error}")
        raise error

@pytest.mark.skip()
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_ble_adv_scan_check_during_TCP_Tx_C769618(
        wifi_dut, utf_constants, sl_collections, ble_clients, ble_dut, wifi_access_point, wifi_client, wifi_sniffer,
        testcase, sniffer_filter, net_perf_client, protocol,ping_count, iter_count ):
    """
        Test Steps:
            1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
            2. Wifi scan & connect to AP.
            3. Enable power save and then start ping from remote device.
            4. Start TCP data transfer from DUT to remote device.
            5. Advertise DUT ,Scan from remote device enable
            6. Advertise remote device & Scan from DUT.
            8.Stop TCP data transfer.

        """
    try:
        wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                  testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                                  protocol=protocol, sl_collections=sl_collections,
                                  ping_count=ping_count, data_transfer=True, traffic_type="TX",
                                  iteration_count=iter_count
                                  )

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_clients=ble_clients, utf_constants=utf_constants,
                                         ble_scan_interval=384, ble_scan_window=128, set_smp=1, ble_conn_interval_min=48, ble_conn_interval_max=48,
                                         test_case=769618)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(20)
        wlan_obj.iperf()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Test completed successfully.")

    except Exception as error:
        logger().error(f"Error in BLE thread functionality: {error}")
        raise error

